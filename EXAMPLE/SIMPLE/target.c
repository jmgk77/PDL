#include <stdio.h>
#include <stdlib.h>
#include <windows.h>

__declspec(dllexport) int __cdecl functionA() { return 0; }

__declspec(dllexport) int __cdecl functionB(int a, int b) { return (a + b); }

__declspec(dllexport) int __cdecl functionC(int a, int b, int c) {
  return (a + b + c);
}

__declspec(dllexport) int __cdecl functionD(int a, int b, int c, int d) {
  return (a + b + c + d);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  switch (fdwReason) {
  case DLL_PROCESS_ATTACH:
    printf("* [TARGET.DLL]\tDLL_PROCESS_ATTACH\n");
    break;

  case DLL_THREAD_ATTACH:
    printf("* [TARGET.DLL]\tDLL_THREAD_ATTACH\n");
    break;

  case DLL_THREAD_DETACH:
    printf("* [TARGET.DLL]\tDLL_THREAD_DETACH\n");
    break;

  case DLL_PROCESS_DETACH:
    printf("* [TARGET.DLL]\tDLL_PROCESS_DETACH\n");
    break;
  }

  return TRUE;
}