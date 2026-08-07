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

#define LOG(...) __android_log_print(ANDROID_LOG_INFO, "AnvilUncapped", __VA_ARGS__)

#define MAX_PATTERN_BYTES 256
#define MAX_QUEUE_ENTRIES 64

uintptr_t GetLibBase(const char* libname = "libminecraftpe.so") {
    FILE* fp = fopen("/proc/self/maps", "r");
    if (!fp) return 0;

    char line[512];
    uintptr_t base = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, libname)) {
            sscanf(line, "%lx", &base);
            break;
        }
    }
    fclose(fp);
    return base;
}

uintptr_t GetLibSection(const char* libname, const char* section_name, size_t* out_size) {
    if (!libname) return 0;
    if (!section_name) section_name = ".text";

    uintptr_t base_addr = 0;
    char lib_path[512] = {0};

    FILE* maps = fopen("/proc/self/maps", "r");
    if (!maps) return 0;

    char line[512];
    while (fgets(line, sizeof(line), maps)) {
        if (strstr(line, libname)) {
            char path[512] = {0};
            if (sscanf(line, "%llx-%*x %*s %*x %*s %*d %511s", (unsigned long long*)&base_addr, path) >= 1) {
                if (path[0] == '/') {
                    strncpy(lib_path, path, sizeof(lib_path) - 1);
                    break;
                }
            }
        }
    }
    fclose(maps);

    if (lib_path[0] == '\0' || base_addr == 0) return 0;

    int fd = open(lib_path, O_RDONLY);
    if (fd < 0) return 0;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return 0;
    }

    void* map_base = mmap(nullptr, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (map_base == MAP_FAILED) return 0;

    uintptr_t section_runtime_addr = 0;
    ElfW(Ehdr)* ehdr = (ElfW(Ehdr)*)map_base;

    if (memcmp(ehdr->e_ident, ELFMAG, SELFMAG) == 0 && ehdr->e_shstrndx != SHN_UNDEF) {
        ElfW(Shdr)* shdr = (ElfW(Shdr)*)((uintptr_t)map_base + ehdr->e_shoff);
        
        if (ehdr->e_shstrndx < ehdr->e_shnum) {
            const char* shstrtab = (const char*)((uintptr_t)map_base + shdr[ehdr->e_shstrndx].sh_offset);

            for (int i = 0; i < ehdr->e_shnum; i++) {
                const char* current_section_name = shstrtab + shdr[i].sh_name;
                if (strcasecmp(current_section_name, section_name) == 0) {
                    section_runtime_addr = base_addr + shdr[i].sh_addr;
                    if (out_size) *out_size = shdr[i].sh_size;
                    break;
                }
            }
        }
    }

    munmap(map_base, st.st_size);
    return section_runtime_addr;
}

namespace Pattern {

    struct Byte {
        uint8_t value;
        uint8_t mask;
    };

    struct Signature {
        Byte bytes[MAX_PATTERN_BYTES];
        size_t size;
    };

    static int Hex(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        c |= 0x20;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    Signature Parse(const char* pattern) {
        Signature out{};
        out.size = 0;

        while (*pattern && out.size < MAX_PATTERN_BYTES) {
            while (*pattern == ' ') pattern++;
            if (!*pattern) break;

            Byte p{};
            if (pattern[0] == '?' && pattern[1] == '?') {
                p.mask = 0x00;
                p.value = 0x00;
                pattern += 2;
            } else if (pattern[0] == '?') {
                p.mask = 0x0F;
                p.value = Hex(pattern[1]);
                pattern += 2;
            } else if (pattern[1] == '?' || pattern[1] == ' ' || pattern[1] == '\0') {
                p.mask = 0xF0;
                p.value = Hex(pattern[0]) << 4;
                pattern += (pattern[1] == '?') ? 2 : 1;
            } else {
                p.mask = 0xFF;
                p.value = (Hex(pattern[0]) << 4) | Hex(pattern[1]);
                pattern += 2;
            }
            out.bytes[out.size++] = p;
        }
        return out;
    }

    uintptr_t Find(const Signature& sig) {
        static thread_local uintptr_t text = 0;
        static thread_local size_t size = 0;
        static thread_local uintptr_t cursor = 0;

        if (!text) text = GetLibSection("libminecraftpe.so", ".text", &size);
        if (!text || !size || sig.size == 0) return 0;

        uintptr_t end = text + size;

        if (cursor < text || cursor >= end) {
            cursor = text;
        }

        uint8_t first_val = sig.bytes[0].value;
        uint8_t first_mask = sig.bytes[0].mask;

        auto MatchesAt = [&](uintptr_t p) -> bool {
            if ((*(uint8_t*)p & first_mask) != (first_val & first_mask)) return false;

            for (size_t j = 1; j < sig.size; j++) {
                uint8_t b = *(uint8_t*)(p + j);
                if ((b & sig.bytes[j].mask) != (sig.bytes[j].value & sig.bytes[j].mask)) {
                    return false;
                }
            }
            return true;
        };

        for (uintptr_t p = cursor; p + sig.size <= end; p += 4) {
            if (MatchesAt(p)) {
                cursor = p + sig.size;
                return p;
            }
        }

        for (uintptr_t p = text; p < cursor && p + sig.size <= end; p += 4) {
            if (MatchesAt(p)) {
                cursor = p + sig.size;
                return p;
            }
        }

        return 0;
    }
}

namespace Patch {

    struct Entry {
        const char* search;
        const char* replace;
    };

    static Entry queue[MAX_QUEUE_ENTRIES];
    static size_t count = 0;

    void Queue(const char* search, const char* replace) {
        if (count < MAX_QUEUE_ENTRIES) {
            queue[count++] = { search, replace };
        } else {
            LOG("Queue overflow: skipped patch %s", search);
        }
    }

    void Execute() {
        uintptr_t base = GetLibBase("libminecraftpe.so");
        size_t pagesize = sysconf(_SC_PAGESIZE);
    
        for (size_t i = 0; i < count; i++) {
            Pattern::Signature search = Pattern::Parse(queue[i].search);
            Pattern::Signature replace = Pattern::Parse(queue[i].replace);
    
            uintptr_t addr = Pattern::Find(search);
            if (!addr) continue;
    
            LOG("Found %s at offset 0x%lX", queue[i].search, (unsigned long)(addr - base));
    
            size_t max_bytes = (search.size > replace.size) ? search.size : replace.size;
            uintptr_t page = addr & ~(pagesize - 1);
            size_t len = ((addr + max_bytes + pagesize - 1) & ~(pagesize - 1)) - page;
    
            if (mprotect((void*)page, len, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                LOG("Failed mprotect at 0x%lX", (unsigned long)(addr - base));
                continue;
            }
    
            for (size_t j = 0; j < replace.size; j++) {
                if (replace.bytes[j].mask != 0x00) {
                    if (replace.bytes[j].mask == 0xFF) {
                        ((uint8_t*)addr)[j] = replace.bytes[j].value;
                    } else {
                        uint8_t orig = ((uint8_t*)addr)[j];
                        uint8_t mask = replace.bytes[j].mask;
                        uint8_t val  = replace.bytes[j].value;
                        ((uint8_t*)addr)[j] = (orig & ~mask) | (val & mask);
                    }
                }
            }
    
            mprotect((void*)page, len, PROT_READ | PROT_EXEC);
            
            __builtin___clear_cache((char*)addr, (char*)(addr + max_bytes));
        }
    
        count = 0;
    }
}

void HookInfinite () {
    // AnvilContainerManagerController::updatePreviewItem
    // Lvl 39 clamp
    Patch::Queue("6B 00 00 54 E8 04 80 52", "1F 20 03 D5 1F 20 03 D5"); // removes lvl 39 clamp & show true cost for overworked singular rename
    // Lvl 40 check
    Patch::Queue("CB 00 00 54 08 00 40 F9", "06 00 00 14");             // isTooExpensive check
    
    // AnvilContainerManagerController::getCostText
    Patch::Queue("EB 02 00 54 08 00 40 F9", "17 00 00 14");             // isTooExpensive check
    
    // RedGreenAnvil
    Patch::Queue("AB 01 00 54 08 00 40 F9", "0D 00 00 14");             // show green regardless >=40 and if enough player xp
    Patch::Queue("AA FE FF 54 34 00 80 52", "1F 20 03 D5");             // isTooExpensive check
    
    // AnvilContainerManagerController::shouldDrawRed
    Patch::Queue("2A 01 00 54 F6 03 1F 2A", "1F 20 03 D5");             // isTooExpensive check
    
    // AnvilContainerScreenValidator::getCraftResult
    // Lvl 39 clamp
    Patch::Queue("?? 11 ?? 1A ?? 01 00 37 ?? ?? 00 71", "F7 03 1? 2A");                         // pass on true rename cost, not the clamped one
    // Lvl 40 check
    Patch::Queue("60 00 00 36 ?? 03 ?? 2A 07 00 00 14 ?? ?? ?? 39", "1F 20 03 D5");             // isTooExpensive check
    // Lvl 39 clamp
    Patch::Queue("?? ?? 00 54 E8 ?? ?? 39 ?? 11 00 ?? ?? ?? ?? F9 ?? ?? ?? B4", "1F 20 03 D5"); // removes lvl 39 clamp for singular rename

    Patch::Execute();
}

__attribute__((constructor))
void init() {
    HookInfinite();
    LOG("Mod initialized successfully.");
}