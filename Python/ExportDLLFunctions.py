# Title: ExportDLLFunctions.py
# Author: misthi0s
# Date: 9/19/2025
# Description: Create pragma statements for C++ DLLs to enable DLL proxying. Takes input of a legitimate DLL file, grabs all its exports, creates the statements, then outputs them all to a file for easy copy/paste into cpp file.
# Requirements: pip install pefile
# Version: 1.0

import pefile
import argparse
import os

def parse_exports(dll_path, output_file):
	if os.path.exists(output_file):
		os.remove(output_file)
	pe = pefile.PE(dll_path)
	dll_file_name = dll_path.split('.')[0]
	escaped_dll_file_name = dll_file_name.replace("\\", "\\\\")

	with open(output_file, "a") as file:
		if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
			for export in pe.DIRECTORY_ENTRY_EXPORT.symbols:
				function_name = export.name.decode('utf-8') if export.name else None
				ordinal = export.ordinal
				print(function_name)
				file.write('#pragma comment(linker, "/export:{}={}.{},@{}")\n'.format(function_name, escaped_dll_file_name, function_name, ordinal))

parser = argparse.ArgumentParser(description="Create pragma statements of DLL functions for DLL proxying")
parser.add_argument("-i", "--input", type=str, help="original DLL to proxy")
parser.add_argument("-o", "--output", type=str, help="output file to save results (default: exports.txt)", default="exports.txt")

args = parser.parse_args()

parse_exports(args.input, args.output)