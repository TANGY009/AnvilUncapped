#include "patch.h"

#ifdef _WIN32
namespace Logger {
    HANDLE hConsole = INVALID_HANDLE_VALUE;

    void Init() {
        AllocConsole();
        hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    }

    void Log(const char* level, const char* fmt, ...) {
        if (hConsole == INVALID_HANDLE_VALUE) return;

        char msg[1024];
        va_list args;
        va_start(args, fmt);
        vsnprintf(msg, sizeof(msg), fmt, args);
        va_end(args);

        SYSTEMTIME st;
        GetLocalTime(&st);

        char finalLine[1200];
        int len = snprintf(finalLine, sizeof(finalLine), "%02d:%02d:%02d.%03d %s [%s] %s\n", 
                            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds, 
                            level, MOD_NAME, msg);

        DWORD written;
        WriteFile(hConsole, finalLine, static_cast<DWORD>(len), &written, nullptr);
    }
}
#endif

#ifdef __ANDROID__
uintptr_t GetLibBase(const char* libname) {
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
#elif defined(_WIN32)
namespace Memory {
    bool GetSectionBounds(HMODULE hModule, const char* sectionName, uintptr_t& outBase, size_t& outSize) {
        if (!hModule) return false;
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew);
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            if (lstrcmpA(reinterpret_cast<const char*>(sectionHeader[i].Name), sectionName) == 0) {
                outBase = reinterpret_cast<uintptr_t>(hModule) + sectionHeader[i].VirtualAddress;
                outSize = sectionHeader[i].Misc.VirtualSize;
                return true;
            }
        }
        return false;
    }

    uintptr_t RvaToFileOffset(HMODULE hModule, uintptr_t rva) {
        if (!hModule) return 0;

        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(hModule) + dosHeader->e_lfanew
        );
        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

        auto sectionHeader = IMAGE_FIRST_SECTION(ntHeaders);
        for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i) {
            DWORD secRva = sectionHeader[i].VirtualAddress;
            DWORD secSize = sectionHeader[i].Misc.VirtualSize;

            if (rva >= secRva && rva < (secRva + secSize)) {
                return (rva - secRva) + sectionHeader[i].PointerToRawData;
            }
        }
        return 0;
    }

    bool IsServerExecutable() {
        wchar_t path[MAX_PATH];
        if (GetModuleFileNameW(nullptr, path, MAX_PATH) == 0) return false;

        wchar_t* filename = wcsrchr(path, L'\\');
        filename = (filename != nullptr) ? filename + 1 : path;

        return (_wcsicmp(filename, L"bedrock_server.exe") == 0);
    }
}
#endif

namespace Pattern {
#ifdef __ANDROID__
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
#elif defined(_WIN32)
    namespace Detail {
        uint8_t HexToNibble(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return 0;
        }

        bool IsSpace(char c) {
            return c == ' ' || c == '\t' || c == '\n' || c == '\r';
        }

        int GetByteRarityScore(uint8_t byte) {
            if (byte == 0x00 || byte == 0xFF || byte == 0xCC || byte == 0x90) return 100;
            if (byte >= 0x48 && byte <= 0x4F) return 80; 
            if (byte >= 0x50 && byte <= 0x5F) return 70; 
            if (byte == 0x8B || byte == 0x89 || byte == 0xE8) return 60;
            return 10;
        }
    }

    Signature Parse(const char* sig) {
        Signature pattern{};
        size_t i = 0;

        while (sig[i] != '\0' && pattern.length < MAX_PATTERN_BYTES) {
            while (sig[i] != '\0' && Detail::IsSpace(sig[i])) i++;
            if (sig[i] == '\0') break;

            if (sig[i] == '?') {
                pattern.bytes[pattern.length] = 0x00;
                pattern.mask[pattern.length] = false;
                i += (sig[i + 1] == '?') ? 2 : 1;
            } else {
                uint8_t high = Detail::HexToNibble(sig[i]);
                uint8_t low = Detail::HexToNibble(sig[i + 1]);
                pattern.bytes[pattern.length] = static_cast<uint8_t>((high << 4) | low);
                pattern.mask[pattern.length] = true;
                i += 2;
            }
            pattern.length++;
        }
        pattern.size = pattern.length;

        int bestRarity1 = 999;
        int bestRarity2 = 999;

        for (size_t idx = 0; idx < pattern.length; ++idx) {
            if (pattern.mask[idx]) {
                int rarity = Detail::GetByteRarityScore(pattern.bytes[idx]);
                if (rarity < bestRarity1) {
                    bestRarity2 = bestRarity1;
                    pattern.anchorOffset2 = pattern.anchorOffset1;
                    pattern.anchorByte2 = pattern.anchorByte1;

                    bestRarity1 = rarity;
                    pattern.anchorOffset1 = idx;
                    pattern.anchorByte1 = pattern.bytes[idx];
                } else if (rarity < bestRarity2 && idx != pattern.anchorOffset1) {
                    bestRarity2 = rarity;
                    pattern.anchorOffset2 = idx;
                    pattern.anchorByte2 = pattern.bytes[idx];
                }
            }
        }

        return pattern;
    }

    uintptr_t FindSSE2(uintptr_t base, size_t size, const Signature& pattern) {
        if (pattern.length == 0 || size < pattern.length) return 0;

        const size_t maxAnchor = (pattern.anchorOffset1 > pattern.anchorOffset2) ? pattern.anchorOffset1 : pattern.anchorOffset2;
        if (size < maxAnchor + 16) return 0;

        const uint8_t* scanStart = reinterpret_cast<const uint8_t*>(base);
        const size_t scanLimit = size - pattern.length;

        const __m128i targetVec1 = _mm_set1_epi8(static_cast<char>(pattern.anchorByte1));
        const __m128i targetVec2 = _mm_set1_epi8(static_cast<char>(pattern.anchorByte2));
        const size_t anchor1 = pattern.anchorOffset1;
        const size_t anchor2 = pattern.anchorOffset2;

        auto ProcessBitmask = [&](unsigned long bitmask, size_t offset) -> uintptr_t {
            unsigned long bitIndex;
            while (_BitScanForward(&bitIndex, bitmask)) {
                size_t candidateIdx = offset + bitIndex;

                if (candidateIdx <= scanLimit) {
                    bool match = true;
                    for (size_t j = 0; j < pattern.length; ++j) {
                        if (pattern.mask[j] && scanStart[candidateIdx + j] != pattern.bytes[j]) {
                            match = false;
                            break;
                        }
                    }
                    if (match) return reinterpret_cast<uintptr_t>(&scanStart[candidateIdx]);
                }
                bitmask &= (bitmask - 1);
            }
            return 0;
        };

        size_t i = 0;
        const size_t simdLimit = (size >= maxAnchor + 16) ? (size - maxAnchor - 16) : 0;

        for (; i + 31 <= simdLimit; i += 32) {
            __m128i mem1_a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&scanStart[i + anchor1]));
            __m128i mem1_b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&scanStart[i + anchor2]));
            __m128i eq1 = _mm_and_si128(_mm_cmpeq_epi8(mem1_a, targetVec1), _mm_cmpeq_epi8(mem1_b, targetVec2));
            unsigned long mask1 = static_cast<unsigned long>(_mm_movemask_epi8(eq1));

            if (mask1 != 0) {
                uintptr_t res = ProcessBitmask(mask1, i);
                if (res) return res;
            }

            __m128i mem2_a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&scanStart[i + 16 + anchor1]));
            __m128i mem2_b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&scanStart[i + 16 + anchor2]));
            __m128i eq2 = _mm_and_si128(_mm_cmpeq_epi8(mem2_a, targetVec1), _mm_cmpeq_epi8(mem2_b, targetVec2));
            unsigned long mask2 = static_cast<unsigned long>(_mm_movemask_epi8(eq2));

            if (mask2 != 0) {
                uintptr_t res = ProcessBitmask(mask2, i + 16);
                if (res) return res;
            }
        }

        for (; i + 15 <= simdLimit; i += 16) {
            __m128i mem_a = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&scanStart[i + anchor1]));
            __m128i mem_b = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&scanStart[i + anchor2]));
            __m128i eq = _mm_and_si128(_mm_cmpeq_epi8(mem_a, targetVec1), _mm_cmpeq_epi8(mem_b, targetVec2));
            unsigned long mask = static_cast<unsigned long>(_mm_movemask_epi8(eq));

            if (mask != 0) {
                uintptr_t res = ProcessBitmask(mask, i);
                if (res) return res;
            }
        }

        for (; i <= scanLimit; ++i) {
            bool match = true;
            for (size_t j = 0; j < pattern.length; ++j) {
                if (pattern.mask[j] && scanStart[i + j] != pattern.bytes[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return reinterpret_cast<uintptr_t>(&scanStart[i]);
        }

        return 0;
    }

    uintptr_t Find(const Signature& sig) {
        uintptr_t base = 0;
        size_t size = 0;
        if (Memory::GetSectionBounds(GetModuleHandleW(nullptr), ".text", base, size)) {
            return FindSSE2(base, size, sig);
        }
        return 0;
    }
#endif
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

#ifdef __ANDROID__
    void Execute() {
        uintptr_t base = GetLibBase("libminecraftpe.so");
        size_t pagesize = sysconf(_SC_PAGESIZE);
        
        for (size_t i = 0; i < count; i++) {
            Pattern::Signature search = Pattern::Parse(queue[i].search);
            Pattern::Signature replace = Pattern::Parse(queue[i].replace);
    
            uintptr_t addr = Pattern::Find(search);
            if (!addr) continue;
    
            LOG("Found %s at 0x%lX", queue[i].search, (unsigned long)(addr - base));
    
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
#elif defined(_WIN32)
    void Execute(HMODULE hModule, const char* section) {
        uintptr_t textBase = 0;
        size_t textSize = 0;

        if (!Memory::GetSectionBounds(hModule, section, textBase, textSize)) return;

        uintptr_t moduleBase = reinterpret_cast<uintptr_t>(hModule);
        uintptr_t currentCursor = textBase;
        uintptr_t textEnd = textBase + textSize;

        for (size_t i = 0; i < count; i++) {
            Pattern::Signature searchPattern = Pattern::Parse(queue[i].search);
            Pattern::Signature replacePattern = Pattern::Parse(queue[i].replace);

            uintptr_t foundAddr = 0;

            if (currentCursor >= textBase && currentCursor < textEnd) {
                size_t remainingSize = textEnd - currentCursor;
                foundAddr = Pattern::FindSSE2(currentCursor, remainingSize, searchPattern);
            }

            if (!foundAddr && currentCursor > textBase) {
                foundAddr = Pattern::FindSSE2(textBase, textSize, searchPattern);
            }

            if (!foundAddr) {
                LOG("Failed to find pattern: %s", queue[i].search);
                continue;
            }

            uintptr_t rva = foundAddr - moduleBase;
            uintptr_t fileOffset = Memory::RvaToFileOffset(hModule, rva);

            DWORD oldProtect;
            if (VirtualProtect(reinterpret_cast<LPVOID>(foundAddr), replacePattern.length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                for (size_t j = 0; j < replacePattern.length; ++j) {
                    if (replacePattern.mask[j]) {
                        *reinterpret_cast<uint8_t*>(foundAddr + j) = replacePattern.bytes[j];
                    }
                }
                VirtualProtect(reinterpret_cast<LPVOID>(foundAddr), replacePattern.length, oldProtect, &oldProtect);

                currentCursor = foundAddr + searchPattern.length;

                LOG("Found %s at 0x%llX", queue[i].search, static_cast<unsigned long long>(fileOffset));
            } else {
                LOG("Failed VirtualProtect at 0x%llX", static_cast<unsigned long long>(fileOffset));
            }
        }

        count = 0;
    }
#endif
}