import os
import sys
import argparse
import pefile

def main():
    parser = argparse.ArgumentParser( description = 'Extracts shellcode from an Object File.' );
    parser.add_argument( '-f', required = True, help = 'Path to the source executable', type = str );
    parser.add_argument( '-o', required = True, help = 'Path to store the output raw binary', type = str );
    options = parser.parse_args();
    print(options.f)

    with open(options.f, 'rb') as f:
        pe=pefile.PE(options.f)
        text=pe.sections[0]
        print(text)
        print(hex(text.PointerToRawData))
        print(hex(text.SizeOfRawData))

        f.seek(text.PointerToRawData)
        data = f.read(text.SizeOfRawData)
        fnew=open(options.o,'wb')
        fnew.write(data)

main()