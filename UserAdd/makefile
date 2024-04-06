all:
	@ mkdir -p build
	@ x86_64-w64-mingw32-g++ -std=c++11 -w -Wall -Wextra main.cxx ../Shared/log.c -o build/UserAdd.exe
	@ python3 ../DllLdr/tests/appendfile.py -s ../DllLdr/build/DllLdr.x64.bin -w build/UserAdd.exe -o build/UserAdd.o
