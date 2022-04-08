#!/bin/sh
wine ../../proxify.exe -i target.dll -o temp.dll -m malware.dll -d proxy.dll -s exports -v
mv target.dll proxy.dll
mv temp.dll target.dll
