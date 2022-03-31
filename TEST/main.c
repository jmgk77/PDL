#include <stdio.h>
#include <stdlib.h>

__declspec(dllimport) int __cdecl functionA();
__declspec(dllimport) int __cdecl functionB(int a, int b);
__declspec(dllimport) int __cdecl functionC(int a, int b, int c);
__declspec(dllimport) int __cdecl functionD(int a, int b, int c, int d);

int main(int argc, char **argv) {
  if (functionA() + functionB(0, 0) + functionC(0, 0, 0) +
          functionD(0, 0, 0, 0) ==
      0) {
    printf("* [MAIN.EXE]\n");
  }
  return EXIT_SUCCESS;
}