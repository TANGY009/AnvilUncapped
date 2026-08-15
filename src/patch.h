#pragma once

#ifdef __ANDROID__
#include <stdint.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <dlfcn.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <elf.h>
#include <link.h>
#include <strings.h>
#include <android/log.h>
#include <arm_neon.h>
#elif defined(_WIN32)
#include <windows.h>
#include <emmintrin.h>
#include <intrin.h>
#include <cstdint>
#include <cstdio>
#include <cwchar>
#endif

#define MOD_NAME "AnvilUncapped"
#define MAX_PATTERN_BYTES 256
#define MAX_QUEUE_ENTRIES 64

#ifdef __ANDROID__
#define LOG(...) __android_log_print(ANDROID_LOG_INFO, MOD_NAME, __VA_ARGS__)
#elif defined(_WIN32)
namespace Logger {
    void Log(const char* level, const char* fmt, ...);
}
#define LOG(...) Logger::Log("INFO", __VA_ARGS__)
#endif

#ifdef __ANDROID__
uintptr_t GetLibBase(const char* libname = "libminecraftpe.so");
uintptr_t GetLibSection(const char* libname, const char* section_name, size_t* out_size);
#elif defined(_WIN32)
namespace Memory {
    bool GetSectionBounds(HMODULE hModule, const char* sectionName, uintptr_t& outBase, size_t& outSize);
    uintptr_t RvaToFileOffset(HMODULE hModule, uintptr_t rva);
    bool IsServerExecutable();
}
#endif

namespace Pattern {
#ifdef __ANDROID__
    struct Byte {
        uint8_t value;
        uint8_t mask;
    };
    struct Signature {
        Byte bytes[MAX_PATTERN_BYTES];
        size_t size;
        size_t anchor_offset;
    };
#elif defined(_WIN32)
    struct Signature {
        uint8_t bytes[MAX_PATTERN_BYTES];
        bool mask[MAX_PATTERN_BYTES];
        size_t length;
        size_t size;
        size_t anchorOffset1;
        uint8_t anchorByte1;
        size_t anchorOffset2;
        uint8_t anchorByte2;
    };
    uintptr_t FindSSE2(uintptr_t base, size_t size, const Signature& pattern);
#endif
    Signature Parse(const char* sig);
    uintptr_t Find(const Signature& sig);
}

namespace Patch {
    void Queue(const char* search, const char* replace);
#ifdef __ANDROID__
    void Execute();
#elif defined(_WIN32)
    void Execute(HMODULE hModule = GetModuleHandleW(nullptr), const char* section = ".text");
#endif
}