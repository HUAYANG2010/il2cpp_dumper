//
// elf_remote.cpp
//
#include "elf_remote.h"

#include <elf.h>
#include <fcntl.h>
#include <unistd.h>

#include <cstdio>
#include <cstring>

RemoteMemory::RemoteMemory(pid_t pid) : pid_(pid) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", (int)pid);
    // 读写都需要，root 下可用
    fd_ = open(path, O_RDWR | O_CLOEXEC);
    if (fd_ < 0) fd_ = open(path, O_RDONLY | O_CLOEXEC);
}

RemoteMemory::~RemoteMemory() {
    if (fd_ >= 0) close(fd_);
}

bool RemoteMemory::read(uintptr_t addr, void* buf, size_t len) const {
    if (fd_ < 0 || len == 0) return false;
    char* p = static_cast<char*>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd_, p + done, len - done, (off_t)(addr + done));
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

bool RemoteMemory::write(uintptr_t addr, const void* buf, size_t len) const {
    if (fd_ < 0 || len == 0) return false;
    const char* p = static_cast<const char*>(buf);
    size_t done = 0;
    while (done < len) {
        ssize_t n = pwrite(fd_, p + done, len - done, (off_t)(addr + done));
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

bool RemoteMemory::readCStr(uintptr_t addr, std::string& out, size_t maxLen) const {
    out.clear();
    char buf[64];
    size_t off = 0;
    while (off < maxLen) {
        size_t chunk = sizeof(buf) - 1;
        if (chunk > maxLen - off) chunk = maxLen - off;
        // 逐字节读取代价太高，先按块读，但要避免跨未映射页导致失败
        if (!read(addr + off, buf, chunk)) {
            // 退化为逐字节
            for (size_t i = 0; i < chunk; ++i) {
                char c;
                if (!read(addr + off + i, &c, 1)) return !out.empty();
                if (c == '\0') return true;
                out.push_back(c);
            }
            off += chunk;
            continue;
        }
        for (size_t i = 0; i < chunk; ++i) {
            if (buf[i] == '\0') return true;
            out.push_back(buf[i]);
        }
        off += chunk;
    }
    return !out.empty();
}

bool RemoteMemory::readU32(uintptr_t addr, uint32_t* out) const {
    return read(addr, out, sizeof(uint32_t));
}

namespace {

struct SymEntry {
    uint32_t st_name = 0;
    uint64_t st_value = 0;
    uint16_t st_shndx = 0;
};

bool readSym(RemoteMemory& mem, const RemoteElf& elf, uint32_t idx, SymEntry* out) {
    if (elf.is64) {
        Elf64_Sym s;
        if (!mem.read(elf.symtab + (uintptr_t)idx * sizeof(s), &s, sizeof(s))) return false;
        out->st_name = s.st_name;
        out->st_value = s.st_value;
        out->st_shndx = s.st_shndx;
    } else {
        Elf32_Sym s;
        if (!mem.read(elf.symtab + (uintptr_t)idx * sizeof(s), &s, sizeof(s))) return false;
        out->st_name = s.st_name;
        out->st_value = s.st_value;
        out->st_shndx = s.st_shndx;
    }
    return true;
}

bool nameMatches(RemoteMemory& mem, const RemoteElf& elf, uint32_t stName, const char* name) {
    if (stName == 0) return false;
    if (elf.strtabSize && stName >= elf.strtabSize) return false;
    std::string s;
    if (!mem.readCStr(elf.strtab + stName, s, 512)) return false;
    return s == name;
}

uint32_t gnuHashOf(const char* name) {
    uint32_t h = 5381;
    const unsigned char* p = (const unsigned char*)name;
    while (*p) h = h * 33 + *p++;
    return h;
}

uint32_t sysvHashOf(const char* name) {
    uint32_t h = 0, g;
    const unsigned char* p = (const unsigned char*)name;
    while (*p) {
        h = (h << 4) + *p++;
        g = h & 0xf0000000u;
        h ^= g;
        h ^= g >> 24;
    }
    return h;
}

} // namespace

bool remoteElfInit(RemoteMemory& mem, uintptr_t loadBias, RemoteElf* elf) {
    unsigned char head[64];
    if (!mem.read(loadBias, head, sizeof(head))) return false;
    if (memcmp(head, ELFMAG, SELFMAG) != 0) return false;

    elf->load_bias = loadBias;
    elf->is64 = (head[EI_CLASS] == ELFCLASS64);

    uint64_t phoff = 0;
    uint16_t phentsize = 0, phnum = 0;
    if (elf->is64) {
        Elf64_Ehdr eh;
        memcpy(&eh, head, sizeof(eh));
        phoff = eh.e_phoff;
        phentsize = eh.e_phentsize;
        phnum = eh.e_phnum;
    } else {
        Elf32_Ehdr eh;
        memcpy(&eh, head, sizeof(eh));
        phoff = eh.e_phoff;
        phentsize = eh.e_phentsize;
        phnum = eh.e_phnum;
    }
    if (phnum == 0 || phnum > 512) return false;
    if (phentsize < (elf->is64 ? sizeof(Elf64_Phdr) : sizeof(Elf32_Phdr))) return false;

    uint64_t dynVaddr = 0, dynSize = 0;
    for (uint16_t i = 0; i < phnum; ++i) {
        unsigned char ph[64];
        if (!mem.read(loadBias + phoff + (uint64_t)i * phentsize, ph, phentsize)) return false;
        if (elf->is64) {
            Elf64_Phdr p;
            memcpy(&p, ph, sizeof(p));
            if (p.p_type == PT_DYNAMIC) {
                dynVaddr = p.p_vaddr;
                dynSize = p.p_memsz;
            }
        } else {
            Elf32_Phdr p;
            memcpy(&p, ph, sizeof(p));
            if (p.p_type == PT_DYNAMIC) {
                dynVaddr = p.p_vaddr;
                dynSize = p.p_memsz;
            }
        }
    }
    if (dynVaddr == 0 || dynSize == 0) return false;

    uintptr_t dynAddr = loadBias + (uintptr_t)dynVaddr;
    size_t entSize = elf->is64 ? sizeof(Elf64_Dyn) : sizeof(Elf32_Dyn);
    size_t count = (size_t)(dynSize / entSize);
    if (count > 1024) count = 1024;

    for (size_t i = 0; i < count; ++i) {
        int64_t tag;
        uint64_t val;
        if (elf->is64) {
            Elf64_Dyn d;
            if (!mem.read(dynAddr + i * entSize, &d, sizeof(d))) return false;
            tag = d.d_tag;
            val = d.d_un.d_ptr;
        } else {
            Elf32_Dyn d;
            if (!mem.read(dynAddr + i * entSize, &d, sizeof(d))) return false;
            tag = (int32_t)d.d_tag;
            val = d.d_un.d_ptr;
        }
        if (tag == DT_NULL) break;
        switch (tag) {
            case DT_SYMTAB: elf->symtab = loadBias + (uintptr_t)val; break;
            case DT_STRTAB: elf->strtab = loadBias + (uintptr_t)val; break;
            case DT_STRSZ:  elf->strtabSize = (size_t)val; break;
            case DT_HASH:   elf->sysvHash = loadBias + (uintptr_t)val; break;
            case DT_GNU_HASH: elf->gnuHash = loadBias + (uintptr_t)val; break;
            default: break;
        }
    }

    return elf->symtab != 0 && elf->strtab != 0 &&
           (elf->sysvHash != 0 || elf->gnuHash != 0 || elf->strtabSize != 0);
}

uintptr_t remoteElfLookup(RemoteMemory& mem, const RemoteElf& elf, const char* symbolName) {
    if (elf.symtab == 0 || elf.strtab == 0) return 0;

    // ---------- 1) GNU hash ----------
    if (elf.gnuHash) {
        uint32_t nbuckets = 0, symoffset = 0, bloomSize = 0, bloomShift = 0;
        if (mem.readU32(elf.gnuHash, &nbuckets) && mem.readU32(elf.gnuHash + 4, &symoffset) &&
            mem.readU32(elf.gnuHash + 8, &bloomSize) && mem.readU32(elf.gnuHash + 12, &bloomShift) &&
            nbuckets > 0 && bloomSize > 0) {
            const uint32_t bits = elf.is64 ? 64 : 32;
            const uintptr_t bloom = elf.gnuHash + 16;
            const uintptr_t buckets = bloom + (uintptr_t)bloomSize * (elf.is64 ? 8 : 4);
            const uintptr_t chains = buckets + (uintptr_t)nbuckets * 4;

            uint32_t h = gnuHashOf(symbolName);
            uint64_t word = 0;
            if (elf.is64) {
                if (!mem.read(bloom + (uintptr_t)((h / bits) % bloomSize) * 8, &word, 8)) return 0;
            } else {
                uint32_t w32 = 0;
                if (!mem.read(bloom + (uintptr_t)((h / bits) % bloomSize) * 4, &w32, 4)) return 0;
                word = w32;
            }
            uint64_t mask = (uint64_t)1 << (h % bits);
            mask |= (uint64_t)1 << ((h >> bloomShift) % bits);
            if ((word & mask) != mask) return 0;

            uint32_t idx = 0;
            if (!mem.readU32(buckets + (uintptr_t)(h % nbuckets) * 4, &idx)) return 0;
            if (idx < symoffset) return 0;

            for (int guard = 0; guard < 65536; ++guard) {
                uint32_t chain = 0;
                if (!mem.readU32(chains + (uintptr_t)(idx - symoffset) * 4, &chain)) return 0;
                if (((chain | 1u) == (h | 1u))) {
                    SymEntry se;
                    if (readSym(mem, elf, idx, &se) && se.st_shndx != SHN_UNDEF &&
                        nameMatches(mem, elf, se.st_name, symbolName)) {
                        return elf.load_bias + (uintptr_t)se.st_value;
                    }
                }
                if (chain & 1u) break;
                ++idx;
            }
        }
    }

    // ---------- 2) SYSV hash ----------
    if (elf.sysvHash) {
        uint32_t nbucket = 0, nchain = 0;
        if (mem.readU32(elf.sysvHash, &nbucket) && mem.readU32(elf.sysvHash + 4, &nchain) &&
            nbucket > 0 && nchain > 0 && nchain < 0x200000) {
            const uintptr_t buckets = elf.sysvHash + 8;
            const uintptr_t chains = buckets + (uintptr_t)nbucket * 4;
            uint32_t h = sysvHashOf(symbolName);
            uint32_t idx = 0;
            if (mem.readU32(buckets + (uintptr_t)(h % nbucket) * 4, &idx)) {
                for (int guard = 0; guard < 65536 && idx != 0 && idx < nchain; ++guard) {
                    SymEntry se;
                    if (readSym(mem, elf, idx, &se) && se.st_shndx != SHN_UNDEF &&
                        nameMatches(mem, elf, se.st_name, symbolName)) {
                        return elf.load_bias + (uintptr_t)se.st_value;
                    }
                    if (!mem.readU32(chains + (uintptr_t)idx * 4, &idx)) break;
                }
            }
        }
    }

    // ---------- 3) 兜底：线性扫描 ----------
    {
        const uint32_t maxSyms = 65535;
        for (uint32_t i = 0; i < maxSyms; ++i) {
            SymEntry se;
            if (!readSym(mem, elf, i, &se)) break;
            if (se.st_shndx == SHN_UNDEF) continue;
            if (nameMatches(mem, elf, se.st_name, symbolName))
                return elf.load_bias + (uintptr_t)se.st_value;
        }
    }
    return 0;
}

uintptr_t remoteFindSymbol(RemoteMemory& mem, const std::vector<MapEntry>& maps,
                           const char* moduleSuffix, const char* symbolName,
                           uintptr_t* outModuleBase) {
    uintptr_t base = 0;
    std::string path;
    if (!findModule(maps, moduleSuffix, &base, &path)) return 0;
    if (outModuleBase) *outModuleBase = base;

    RemoteElf elf;
    if (!remoteElfInit(mem, base, &elf)) return 0;
    return remoteElfLookup(mem, elf, symbolName);
}