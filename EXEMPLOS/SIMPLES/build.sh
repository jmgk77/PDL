#!/bin/sh
rm *.dll *.exe
x86_64-w64-mingw32-gcc -o target.dll -shared target.c target.def -Wl,--subsystem,windows -s
x86_64-w64-mingw32-gcc -o malware.dll -shared malware.c -Wl,--subsystem,windows -s
x86_64-w64-mingw32-gcc -o main.exe main.c -L. -ltarget -s
