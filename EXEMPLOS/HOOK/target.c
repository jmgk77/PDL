#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

__declspec(dllexport) void __cdecl PrintWelcome() {
  printf("Welcome\nEnter password: ");
}
__declspec(dllexport) void __cdecl PrintOK() { printf("Password accepted\n"); }
__declspec(dllexport) void __cdecl PrintNOK() { printf("Wrong password\n"); }
__declspec(dllexport) int __cdecl CheckPassword(char *buf) {
  return strcmp(buf, "password") == 0 ? 1 : 0;
};

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  return TRUE;
}