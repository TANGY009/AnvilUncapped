#include "main.h"
#include "patch.h"

void HookInfinite() {
#ifdef __ANDROID__
    // AnvilContainerManagerController::updatePreviewItem
    // Lvl 39 clamp
    Patch::Queue("6B 00 00 54 E8 04 80 52", "1F 20 03 D5 1F 20 03 D5"); // removes lvl 39 clamp & show true cost for overworked singular rename
    // Lvl 40 check
    Patch::Queue("6B 01 00 54 08 00 40 F9 08 4D 40 F9 00 01 3F D6 17 00 00 52", "0B 00 00 14"); // isTooExpensive check
    
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
    // Lvl 39 clamp // Seems like not needed anymore?
    //Patch::Queue("?? ?? ?? ?? ?? ?? ?? ?? ?? 12 00 ?? E8 ?? ?? ?? ?? ?? 00 ?? ?? ?? 40 F9 ?? 04 00 B4", "1F 20 03 D5"); // removes lvl 39 clamp for singular rename
#elif defined(_WIN32)
    bool isServer = Memory::IsServerExecutable();

    // AnvilContainerScreenValidator::getCraftResult
    Patch::Queue(
        "BE 27 00 00 00 0F 4C F1 41 84 ?? 0F 44 F1 75 ?? 83 F9 28 7C",
        "89 CE 90 90 90 0F 4C F1 41 84 ?? 0F 44 F1 75 ?? 83 F9 28 EB"
    );

    if (!isServer) {
        // AnvilContainerManagerController::updatePreviewItem
        Patch::Queue("83 F8 28 7C", "83 F8 28 EB");
        Patch::Queue("00 83 BE C8 00 00 00 28 7C", "00 83 BE C8 00 00 00 28 EB");

        // AnvilContainerManagerController::getCostText
        Patch::Queue("45 F? 83 BF C8 00 00 00 28 7C", "45 F? 83 BF C8 00 00 00 28 EB");

        // RedGreenAnvil
        Patch::Queue("01 83 ?? C8 00 00 00 28 7C", "01 83 ?? C8 00 00 00 28 EB");

        // AnvilContainerManagerController::shouldDrawRed
        Patch::Queue("45 ?? 83 BE C8 00 00 00 28 7C", "45 ?? 83 BE C8 00 00 00 28 EB ");
    }
#endif

    Patch::Execute();
}

#ifdef __ANDROID__
__attribute__((constructor))
void init() {
    HookInfinite();
}
#elif defined(_WIN32)
DWORD WINAPI WorkerThread(LPVOID lpParam) {
    HMODULE hModule = reinterpret_cast<HMODULE>(lpParam);
;
    HookInfinite();
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
