CCX64	= x86_64-w64-mingw32-gcc
CCX86	= i686-w64-mingw32-gcc

INCLUDE = -I Include

INCLUDELLVM = -I Include -I/usr/x86_64-w64-mingw32/include -fdeclspec
OPTIONS = -w -Wall -Wextra -masm=intel -fPIC -fno-asynchronous-unwind-tables $(INCLUDE)
OPTIONSLLVM = -w -Wall -Wextra -Wno-int-conversion -masm=intel -fPIC -fno-asynchronous-unwind-tables --target=x86_64-windows-gnu -march=x86-64 -m64 -fms-extensions -e KaynLoader -nostdlib $(INCLUDELLVM)

EXECUTABLE_X64 = build/DllLdr.x64.o
EXECUTABLE_X64LLVM = build/DllLdr.x64.exe
RAWBINARY_X64  = build/DllLdr.x64.bin

all: x64
# No x86 support later
x64: clean
	@ echo "[*] Compile x64 object file..."
	@mkdir -p build
	@ $(CCX64) -c Source/Entry.c -o $(EXECUTABLE_X64) $(OPTIONS)

#   if want to get symbol coff file, comment three line codes below to debug them
	@ echo "[*] Extract shellcode: $(RAWBINARY_X64)"
	@ python3 Scripts/extract.py -f $(EXECUTABLE_X64) -o $(RAWBINARY_X64)
	@ rm $(EXECUTABLE_X64)

llvm:
	@mkdir -p build
	@ echo "[*] Compile x64 object file with llvm ..."
	@clang Source/Entry.c -o $(EXECUTABLE_X64LLVM) $(OPTIONSLLVM) 
	@ echo "[*] Extract clang based shellcode: $(RAWBINARY_X64)"
	@ python3 Scripts/extract_clang.py -f $(EXECUTABLE_X64LLVM) -o $(RAWBINARY_X64)
	@ rm $(EXECUTABLE_X64LLVM)

clean:
	@ rm -rf Bin/*.o
	@ rm -rf Bin/*.bin
