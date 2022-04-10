#include <stdio.h>
#include <stdlib.h>

__declspec(dllimport) int __cdecl functionA();
__declspec(dllimport) int __cdecl functionB(int a, int b);
__declspec(dllimport) int __cdecl functionC(int a, int b, int c);
__declspec(dllimport) int __cdecl functionD(int a, int b, int c, int d);

int main(int argc, char **argv) {
  printf("* [MAIN.EXE] INIT\n");
  if (functionA() + functionB(0, 0) + functionC(0, 0, 0) +
          functionD(0, 0, 0, 0) ==
      0) {
    printf("* [MAIN.EXE] OK\n");
  } else {
    printf("* [MAIN.EXE] NOK\n");
  }
  printf("* [MAIN.EXE] DONE\n");
  return EXIT_SUCCESS;
}