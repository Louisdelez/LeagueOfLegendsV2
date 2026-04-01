/*
 * Fake stub.dll - replaces Riot's anti-cheat stub
 * Exports the same "packman" function but does nothing
 * This allows VirtualProtect to work on .text pages
 *
 * Build: gcc -shared -o stub.dll fake_stub.c -O2
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// The game calls this function at startup
// Real stub.dll sets guard pages on .text, hooks debug APIs, etc.
// Our fake version does nothing.
__declspec(dllexport) void packman(void) {
    // Intentionally empty - no anti-cheat protections
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD reason, LPVOID reserved) {
    return TRUE;
}
