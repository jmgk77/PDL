#include <stdio.h>
#include <stdlib.h>

__declspec(dllimport) void __cdecl PrintWelcome();
__declspec(dllimport) void __cdecl PrintOK();
__declspec(dllimport) void __cdecl PrintNOK();
__declspec(dllimport) int __cdecl CheckPassword(char *);

int main(int argc, char **argv) {
  char buf[20];
  PrintWelcome();
  scanf("%19s", buf);
  if (CheckPassword(buf)) {
    PrintOK();
  } else {
    PrintNOK();
  }
  return EXIT_SUCCESS;
}