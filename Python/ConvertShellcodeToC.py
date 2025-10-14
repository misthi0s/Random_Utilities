# Title: ConvertShellcodeToC.py
# Author: misthi0s
# Date: 10/14/2025
# Description: Convert a raw shellcode file to a C/C++ array statement, allowing for easy copy/pasting of the shellcode into C/C++ code.
# Requirements: N/A
# Version: 1.0

import sys
import argparse

def write_shellcode(infile, outfile, variable_name):
    with open(infile, 'rb') as f:
        shellcode = f.read()

    with open(outfile, 'w') as f:
        f.write(f'unsigned char {variable_name}[] = \n')
        hex_bytes = [f'\\x{byte:02x}' for byte in shellcode]
        lines = [''.join(hex_bytes[i:i+16]) for i in range(0, len(hex_bytes), 16)]
        full_lines = []
        for line in lines:
            if lines[-1] == line:
                full_lines += f'"{line}";'
            else:
                full_lines += f'"{line}"\n'
        f.write(''.join(full_lines))

    print(f"Shellcode written to {outfile}")

parser = argparse.ArgumentParser(description="Convert raw shellcode file to C/C++ array statement")
parser.add_argument("-i", "--input", type=str, help="raw shellcode file")
parser.add_argument("-o", "--output", type=str, help="output file to save shellcode declaration code (default: shellcode.txt)", default="shellcode.txt")
parser.add_argument("-n", "--name", type=str, help="variable name for the output array (default: shellcode)", default="shellcode")

args = parser.parse_args()

write_shellcode(args.input, args.output, args.name)