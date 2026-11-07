//
// il2cpp_dump.cpp  --  在目标进程内调用 il2cpp 导出函数导出 dump.cs
//                       (源自 Perfare/Zygisk-Il2CppDumper，去掉 Zygisk 依赖)
//
#include "il2cpp_dump.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "il2cpp-class.h"
#include "il2cpp-tabledefs.h"
#include "log.h"
#include "xdl.h"

#define DO_API(r, n, p) r (*n) p

#include "il2cpp-api-functions.h"

#undef DO_API

static uint64_t il2cpp_base = 0;

static void init_il2cpp_api(void *handle) {
#define DO_API(r, n, p) {                          \
    n = (r (*) p) xdl_sym(handle, #n, nullptr);    \
    if (!n) {                                      \
        LOGW("api not found %s", #n);              \
    }                                              \
}

#include "il2cpp-api-functions.h"

#undef DO_API
}

std::string get_method_modifier(uint32_t flags) {
    std::stringstream outPut;
    auto access = flags & METHOD_ATTRIBUTE_MEMBER_ACCESS_MASK;
    switch (access) {
        case METHOD_ATTRIBUTE_PRIVATE:
            outPut << "private ";
            break;
        case METHOD_ATTRIBUTE_PUBLIC:
            outPut << "public ";
            break;
        case METHOD_ATTRIBUTE_FAMILY:
            outPut << "protected ";
            break;
        case METHOD_ATTRIBUTE_ASSEM:
        case METHOD_ATTRIBUTE_FAM_AND_ASSEM:
            outPut << "internal ";
            break;
        case METHOD_ATTRIBUTE_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & METHOD_ATTRIBUTE_STATIC) {
        outPut << "static ";
    }
    if (flags & METHOD_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_FINAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_REUSE_SLOT) {
            outPut << "sealed override ";
        }
    } else if (flags & METHOD_ATTRIBUTE_VIRTUAL) {
        if ((flags & METHOD_ATTRIBUTE_VTABLE_LAYOUT_MASK) == METHOD_ATTRIBUTE_NEW_SLOT) {
            outPut << "virtual ";
        } else {
            outPut << "override ";
        }
    }
    if (flags & METHOD_ATTRIBUTE_PINVOKE_IMPL) {
        outPut << "extern ";
    }
    return outPut.str();
}

bool _il2cpp_type_is_byref(const Il2CppType *type) {
    auto byref = type->byref;
    if (il2cpp_type_is_byref) {
        byref = il2cpp_type_is_byref(type);
    }
    return byref;
}

std::string dump_method(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Methods\n";
    void *iter = nullptr;
    while (auto method = il2cpp_class_get_methods(klass, &iter)) {
        if (method->methodPointer) {
            outPut << "\t// RVA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer - il2cpp_base;
            outPut << " VA: 0x";
            outPut << std::hex << (uint64_t) method->methodPointer;
        } else {
            outPut << "\t// RVA: 0x VA: 0x0";
        }
        outPut << "\n\t";
        uint32_t iflags = 0;
        auto flags = il2cpp_method_get_flags(method, &iflags);
        outPut << get_method_modifier(flags);
        auto return_type = il2cpp_method_get_return_type(method);
        if (_il2cpp_type_is_byref(return_type)) {
            outPut << "ref ";
        }
        auto return_class = il2cpp_class_from_type(return_type);
        outPut << il2cpp_class_get_name(return_class) << " " << il2cpp_method_get_name(method)
               << "(";
        auto param_count = il2cpp_method_get_param_count(method);
        for (int i = 0; i < param_count; ++i) {
            auto param = il2cpp_method_get_param(method, i);
            auto attrs = param->attrs;
            if (_il2cpp_type_is_byref(param)) {
                if (attrs & PARAM_ATTRIBUTE_OUT && !(attrs & PARAM_ATTRIBUTE_IN)) {
                    outPut << "out ";
                } else if (attrs & PARAM_ATTRIBUTE_IN && !(attrs & PARAM_ATTRIBUTE_OUT)) {
                    outPut << "in ";
                } else {
                    outPut << "ref ";
                }
            } else {
                if (attrs & PARAM_ATTRIBUTE_IN) {
                    outPut << "[In] ";
                }
                if (attrs & PARAM_ATTRIBUTE_OUT) {
                    outPut << "[Out] ";
                }
            }
            auto parameter_class = il2cpp_class_from_type(param);
            outPut << il2cpp_class_get_name(parameter_class) << " "
                   << il2cpp_method_get_param_name(method, i);
            outPut << ", ";
        }
        if (param_count > 0) {
            outPut.seekp(-2, outPut.cur);
        }
        outPut << ") { }\n";
    }
    return outPut.str();
}

std::string dump_property(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Properties\n";
    void *iter = nullptr;
    while (auto prop_const = il2cpp_class_get_properties(klass, &iter)) {
        auto prop = const_cast<PropertyInfo *>(prop_const);
        auto get = il2cpp_property_get_get_method(prop);
        auto set = il2cpp_property_get_set_method(prop);
        auto prop_name = il2cpp_property_get_name(prop);
        outPut << "\t";
        Il2CppClass *prop_class = nullptr;
        uint32_t iflags = 0;
        if (get) {
            outPut << get_method_modifier(il2cpp_method_get_flags(get, &iflags));
            prop_class = il2cpp_class_from_type(il2cpp_method_get_return_type(get));
        } else if (set) {
            outPut << get_method_modifier(il2cpp_method_get_flags(set, &iflags));
            auto param = il2cpp_method_get_param(set, 0);
            prop_class = il2cpp_class_from_type(param);
        }
        if (prop_class) {
            outPut << il2cpp_class_get_name(prop_class) << " " << prop_name << " { ";
            if (get) {
                outPut << "get; ";
            }
            if (set) {
                outPut << "set; ";
            }
            outPut << "}\n";
        } else {
            if (prop_name) {
                outPut << " // unknown property " << prop_name;
            }
        }
    }
    return outPut.str();
}

std::string dump_field(Il2CppClass *klass) {
    std::stringstream outPut;
    outPut << "\n\t// Fields\n";
    auto is_enum = il2cpp_class_is_enum(klass);
    void *iter = nullptr;
    while (auto field = il2cpp_class_get_fields(klass, &iter)) {
        outPut << "\t";
        auto attrs = il2cpp_field_get_flags(field);
        auto access = attrs & FIELD_ATTRIBUTE_FIELD_ACCESS_MASK;
        switch (access) {
            case FIELD_ATTRIBUTE_PRIVATE:
                outPut << "private ";
                break;
            case FIELD_ATTRIBUTE_PUBLIC:
                outPut << "public ";
                break;
            case FIELD_ATTRIBUTE_FAMILY:
                outPut << "protected ";
                break;
            case FIELD_ATTRIBUTE_ASSEMBLY:
            case FIELD_ATTRIBUTE_FAM_AND_ASSEM:
                outPut << "internal ";
                break;
            case FIELD_ATTRIBUTE_FAM_OR_ASSEM:
                outPut << "protected internal ";
                break;
        }
        if (attrs & FIELD_ATTRIBUTE_LITERAL) {
            outPut << "const ";
        } else {
            if (attrs & FIELD_ATTRIBUTE_STATIC) {
                outPut << "static ";
            }
            if (attrs & FIELD_ATTRIBUTE_INIT_ONLY) {
                outPut << "readonly ";
            }
        }
        auto field_type = il2cpp_field_get_type(field);
        auto field_class = il2cpp_class_from_type(field_type);
        outPut << il2cpp_class_get_name(field_class) << " " << il2cpp_field_get_name(field);
        if (attrs & FIELD_ATTRIBUTE_LITERAL && is_enum) {
            uint64_t val = 0;
            il2cpp_field_static_get_value(field, &val);
            outPut << " = " << std::dec << val;
        }
        outPut << "; // 0x" << std::hex << il2cpp_field_get_offset(field) << "\n";
    }
    return outPut.str();
}

std::string dump_type(const Il2CppType *type) {
    std::stringstream outPut;
    auto *klass = il2cpp_class_from_type(type);
    outPut << "\n// Namespace: " << il2cpp_class_get_namespace(klass) << "\n";
    auto flags = il2cpp_class_get_flags(klass);
    if (flags & TYPE_ATTRIBUTE_SERIALIZABLE) {
        outPut << "[Serializable]\n";
    }
    auto is_valuetype = il2cpp_class_is_valuetype(klass);
    auto is_enum = il2cpp_class_is_enum(klass);
    auto visibility = flags & TYPE_ATTRIBUTE_VISIBILITY_MASK;
    switch (visibility) {
        case TYPE_ATTRIBUTE_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_PUBLIC:
            outPut << "public ";
            break;
        case TYPE_ATTRIBUTE_NOT_PUBLIC:
        case TYPE_ATTRIBUTE_NESTED_FAM_AND_ASSEM:
        case TYPE_ATTRIBUTE_NESTED_ASSEMBLY:
            outPut << "internal ";
            break;
        case TYPE_ATTRIBUTE_NESTED_PRIVATE:
            outPut << "private ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAMILY:
            outPut << "protected ";
            break;
        case TYPE_ATTRIBUTE_NESTED_FAM_OR_ASSEM:
            outPut << "protected internal ";
            break;
    }
    if (flags & TYPE_ATTRIBUTE_ABSTRACT && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "static ";
    } else if (!(flags & TYPE_ATTRIBUTE_INTERFACE) && flags & TYPE_ATTRIBUTE_ABSTRACT) {
        outPut << "abstract ";
    } else if (!is_valuetype && !is_enum && flags & TYPE_ATTRIBUTE_SEALED) {
        outPut << "sealed ";
    }
    if (flags & TYPE_ATTRIBUTE_INTERFACE) {
        outPut << "interface ";
    } else if (is_enum) {
        outPut << "enum ";
    } else if (is_valuetype) {
        outPut << "struct ";
    } else {
        outPut << "class ";
    }
    outPut << il2cpp_class_get_name(klass);
    std::vector<std::string> extends;
    auto parent = il2cpp_class_get_parent(klass);
    if (!is_valuetype && !is_enum && parent) {
        auto parent_type = il2cpp_class_get_type(parent);
        if (parent_type->type != IL2CPP_TYPE_OBJECT) {
            extends.emplace_back(il2cpp_class_get_name(parent));
        }
    }
    void *iter = nullptr;
    while (auto itf = il2cpp_class_get_interfaces(klass, &iter)) {
        extends.emplace_back(il2cpp_class_get_name(itf));
    }
    if (!extends.empty()) {
        outPut << " : " << extends[0];
        for (size_t i = 1; i < extends.size(); ++i) {
            outPut << ", " << extends[i];
        }
    }
    outPut << "\n{";
    outPut << dump_field(klass);
    outPut << dump_property(klass);
    outPut << dump_method(klass);
    outPut << "}\n";
    return outPut.str();
}

// ---------------------------------------------------------------
//  等待 il2cpp 初始化完成
// ---------------------------------------------------------------
static bool wait_il2cpp_ready(int timeoutSec) {
    if (!il2cpp_domain_get || !il2cpp_domain_get_assemblies) return false;
    for (int i = 0; i < timeoutSec; ++i) {
        Il2CppDomain *domain = il2cpp_domain_get();
        if (domain) {
            size_t size = 0;
            il2cpp_domain_get_assemblies(domain, &size);
            if (size > 0) {
                LOGI("il2cpp 已就绪（等待 %d 秒），程序集数量 %zu", i, size);
                return true;
            }
        }
        if (i == 0 || (i % 10) == 0) LOGI("等待 il2cpp 初始化... (%d/%d)", i, timeoutSec);
        sleep(1);
    }
    return false;
}

// ---------------------------------------------------------------
//  把目标进程里映射的文件按文件偏移落盘（用于导出 libil2cpp.so / global-metadata.dat）
// ---------------------------------------------------------------
static bool dump_mapped_file(const std::string &outPath, const char *nameSuffix) {
    struct Seg {
        uintptr_t start;
        uintptr_t end;
        uint64_t offset;
    };
    std::vector<Seg> segs;

    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (!strstr(line, nameSuffix)) continue;
        unsigned long long s = 0, e = 0, o = 0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s %llx", &s, &e, &perms[0], &o) != 4) continue;
        if (perms[0] != 'r') continue;
        segs.push_back({(uintptr_t)s, (uintptr_t)e, (uint64_t)o});
    }
    fclose(fp);
    if (segs.empty()) {
        LOGW("maps 里没有找到 %s，跳过", nameSuffix);
        return false;
    }

    int memfd = open("/proc/self/mem", O_RDONLY);
    if (memfd < 0) return false;
    int outfd = open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (outfd < 0) {
        close(memfd);
        return false;
    }

    const size_t kChunk = 64 * 1024;
    std::vector<char> buf(kChunk);
    for (const auto &s : segs) {
        if (lseek(outfd, (off_t)s.offset, SEEK_SET) < 0) continue;
        uintptr_t addr = s.start;
        while (addr < s.end) {
            size_t n = s.end - addr;
            if (n > kChunk) n = kChunk;
            ssize_t got = pread(memfd, buf.data(), n, (off_t)addr);
            if (got <= 0) {
                addr += n;
                continue;
            }
            if (write(outfd, buf.data(), (size_t)got) != got) break;
            addr += (uintptr_t)got;
        }
    }
    fsync(outfd);
    close(outfd);
    close(memfd);
    LOGI("%s 已导出 -> %s", nameSuffix, outPath.c_str());
    return true;
}

// ---------------------------------------------------------------
//  主流程
// ---------------------------------------------------------------
bool il2cpp_dump_all(void *handle, const char *outDir) {
    LOGI("il2cpp_dump_all 开始, outDir=%s", outDir);
    init_il2cpp_api(handle);

    if (!il2cpp_domain_get || !il2cpp_domain_get_assemblies) {
        LOGE("关键 il2cpp API 缺失，dump 中止（libil2cpp.so 可能还没加载完）");
        return false;
    }

    Dl_info dlInfo;
    if (dladdr((void *) il2cpp_domain_get_assemblies, &dlInfo)) {
        il2cpp_base = reinterpret_cast<uint64_t>(dlInfo.dli_fbase);
    }
    LOGI("il2cpp_base: 0x%" PRIx64, il2cpp_base);

    if (!wait_il2cpp_ready(180)) {
        LOGE("等待 il2cpp 初始化超时");
        return false;
    }

    Il2CppDomain *domain = il2cpp_domain_get();
    if (domain && il2cpp_thread_attach) {
        il2cpp_thread_attach(domain);
        LOGI("已把当前线程 attach 到 il2cpp 域");
    }

    LOGI("开始 dumping...");
    size_t size = 0;
    auto assemblies = il2cpp_domain_get_assemblies(domain, &size);
    if (!assemblies || size == 0) {
        LOGE("取不到程序集列表");
        return false;
    }
    LOGI("程序集数量: %zu", size);

    std::stringstream imageOutput;
    for (size_t i = 0; i < size; ++i) {
        auto image = il2cpp_assembly_get_image(assemblies[i]);
        imageOutput << "// Image " << i << ": " << il2cpp_image_get_name(image) << "\n";
    }

    std::vector<std::string> outPuts;
    if (il2cpp_image_get_class && il2cpp_image_get_class_count) {
        LOGI("il2cpp 版本 >= 2018.3，使用 il2cpp_image_get_class");
        for (size_t i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            imageStr << "\n// Dll : " << il2cpp_image_get_name(image);
            auto classCount = il2cpp_image_get_class_count(image);
            for (size_t j = 0; j < classCount; ++j) {
                auto klass = il2cpp_image_get_class(image, j);
                auto type = il2cpp_class_get_type(const_cast<Il2CppClass *>(klass));
                outPuts.push_back(imageStr.str() + dump_type(type));
            }
        }
    } else {
        LOGI("il2cpp 版本 < 2018.3，使用反射");
        auto corlib = il2cpp_get_corlib();
        auto assemblyClass = il2cpp_class_from_name(corlib, "System.Reflection", "Assembly");
        if (!assemblyClass) {
            LOGE("找不到 System.Reflection.Assembly");
            return false;
        }
        auto assemblyLoad = il2cpp_class_get_method_from_name(assemblyClass, "Load", 1);
        auto assemblyGetTypes = il2cpp_class_get_method_from_name(assemblyClass, "GetTypes", 0);
        if (!assemblyLoad || !assemblyLoad->methodPointer) {
            LOGE("miss Assembly::Load");
            return false;
        }
        if (!assemblyGetTypes || !assemblyGetTypes->methodPointer) {
            LOGE("miss Assembly::GetTypes");
            return false;
        }
        typedef void *(*Assembly_Load_ftn)(void *, Il2CppString *, void *);
        typedef Il2CppArray *(*Assembly_GetTypes_ftn)(void *, void *);
        for (size_t i = 0; i < size; ++i) {
            auto image = il2cpp_assembly_get_image(assemblies[i]);
            std::stringstream imageStr;
            auto image_name = il2cpp_image_get_name(image);
            imageStr << "\n// Dll : " << image_name;
            auto imageName = std::string(image_name);
            auto pos = imageName.rfind('.');
            auto imageNameNoExt = (pos == std::string::npos) ? imageName : imageName.substr(0, pos);
            auto assemblyFileName = il2cpp_string_new(imageNameNoExt.data());
            auto reflectionAssembly = ((Assembly_Load_ftn) assemblyLoad->methodPointer)(
                    nullptr, assemblyFileName, nullptr);
            auto reflectionTypes = ((Assembly_GetTypes_ftn) assemblyGetTypes->methodPointer)(
                    reflectionAssembly, nullptr);
            if (!reflectionTypes) continue;
            auto items = reflectionTypes->vector;
            for (il2cpp_array_size_t j = 0; j < reflectionTypes->max_length; ++j) {
                auto klass = il2cpp_class_from_system_type((Il2CppReflectionType *) items[j]);
                if (!klass) continue;
                auto type = il2cpp_class_get_type(klass);
                outPuts.push_back(imageStr.str() + dump_type(type));
            }
        }
    }

    LOGI("共 %zu 个类型，开始写 dump.cs", outPuts.size());
    auto outPath = std::string(outDir).append("/dump.cs");
    std::ofstream outStream(outPath);
    if (!outStream.is_open()) {
        LOGE("无法写入 %s", outPath.c_str());
        return false;
    }
    outStream << imageOutput.str();
    for (size_t i = 0; i < outPuts.size(); ++i) {
        outStream << outPuts[i];
    }
    outStream.flush();
    outStream.close();
    LOGI("dump.cs 写出完成: %s", outPath.c_str());

    // 可选：把 libil2cpp.so 内存镜像与 global-metadata.dat 一并导出
    std::string flagPath = std::string(outDir).append("/.il2cpp_dump_all");
    if (access(flagPath.c_str(), F_OK) == 0) {
        LOGI("检测到 --all 标记，导出 libil2cpp.so / global-metadata.dat");
        dump_mapped_file(std::string(outDir).append("/libil2cpp.so"), "libil2cpp.so");
        dump_mapped_file(std::string(outDir).append("/global-metadata.dat"), "global-metadata.dat");
    }

    return true;
}