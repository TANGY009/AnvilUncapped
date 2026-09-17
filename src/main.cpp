#include "main.h"
#include "patch.h"

void HookInfinite() {
#ifdef __ANDROID__
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
    Patch::Queue("?? 11 ?? 1A ?? 01 00 37 ?? ?? 00 71", "F? 03 1? 2A");                                                 // pass on true rename cost, not the clamped one
    // Lvl 40 check
    Patch::Queue("60 00 00 36 ?? 03 ?? 2A 07 00 00 14 ?? ?? ?? 39", "1F 20 03 D5");                                     // isTooExpensive check
    // Lvl 39 clamp
    Patch::Queue("?? ?? ?? ?? ?? ?? ?? ?? ?? 11 00 ?? E8 ?? 4? ?9 ?? ?? 00 ?? ?? ?? 40 F9 ?8 03 00 B4", "1F 20 03 D5"); // removes lvl 39 clamp for singular rename
#elif defined(_WIN32)
    bool isServer = Memory::IsServerExecutable();

    // AnvilContainerScreenValidator::getCraftResult
    Patch::Queue(
        "BE 27 00 00 00 0F 4C F1 41 84 C7 0F 44 F1 75 30 83 F9 28 7C 2B",
        "89 CE 90 90 90 0F 4C F1 41 84 C7 0F 44 F1 75 30 83 F9 28 EB 2B"
    );

    if (!isServer) {
        // AnvilContainerManagerController::updatePreviewItem
        Patch::Queue("83 F8 28 7C 0A", "83 F8 28 EB 0A");
        Patch::Queue("83 BE C8 00 00 00 28 7C 1F", "83 BE C8 00 00 00 28 EB 1F");

        // AnvilContainerManagerController::getCostText
        Patch::Queue("48 89 45 F8 83 BF C8 00 00 00 28 7C 36", "48 89 45 F8 83 BF C8 00 00 00 28 EB 36");

        // RedGreenAnvil
        Patch::Queue("48 89 45 E8 40 B6 01 83 BF C8 00 00 00 28 7C 16", "48 89 45 E8 40 B6 01 83 BF C8 00 00 00 28 EB 16");

        // AnvilContainerManagerController::shouldDrawRed
        Patch::Queue("48 89 45 F8 83 BE C8 00 00 00 28 7C 1B", "48 89 45 F8 83 BE C8 00 00 00 28 EB 1B");
    }
#endif

    Patch::Execute();
}

#ifdef __ANDROID__
__attribute__((constructor))
void init() {
    HookInfinite();
    LOG("Mod initialized successfully.");
}
#elif defined(_WIN32)
DWORD WINAPI WorkerThread(LPVOID lpParam) {
    HMODULE hModule = reinterpret_cast<HMODULE>(lpParam);
;
    HookInfinite();
    LOG("Mod initialized successfully.");

    FreeLibraryAndExitThread(hModule, 0);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, WorkerThread, hModule, 0, nullptr);
    }
    return TRUE;
}
#endif