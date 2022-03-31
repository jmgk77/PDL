#!/bin/sh
x86_64-w64-mingw32-gcc -o target.dll -shared target.c -Wl,--subsystem,windows
x86_64-w64-mingw32-gcc -o malware.dll -shared malware.c -Wl,--subsystem,windows
x86_64-w64-mingw32-gcc -o main.exe main.c -L. -ltarget
