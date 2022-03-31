#!/bin/sh
x86_64-w64-mingw32-gcc proxify.c -o proxify.exe -s
gcc proxify.c -o proxify -s
