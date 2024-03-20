import os ,sys
import argparse


parser = argparse.ArgumentParser(description='Append shellcode to weapon dll file');
parser.add_argument('-s', required=True, help='Path to the source executable', type=str);
parser.add_argument('-w', required=True, help='Path to weapon binary', type=str);
parser.add_argument('-o', required=True, help='Path to output binary', type=str);
options = parser.parse_args();

f1=open(options.s,'rb')
f2=open(options.w,'rb')

b1=f1.read()
b2=f2.read()
b3=b1+b2
f3=open(options.o,'wb')
f3.write(b3)
