# Title: GetPPLBinaries.py
# Author: misthi0s
# Date: 10/14/2025
# Description: Check a directory for any signed binaries that can run with PPL privileges (based on certificate Extended Key Usage), and print them to the screen with their associated EKU value.
# Requirements: pip install pefile cryptography asn1crypto
# Version: 1.0

import pefile
import os
import argparse
from asn1crypto import cms
from cryptography import x509
from cryptography.hazmat.backends import default_backend

cert_data = ""

def is_digitally_signed(file_path):
    if not os.path.exists(file_path):
        print(f"Error: File not found at {file_path}")
        return False

    try:
        pe = pefile.PE(file_path, fast_load=True)
        sec_index = pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[sec_index]
        if sec_dir.Size != 0:
            cert_offset = sec_dir.VirtualAddress
            cert_size = sec_dir.Size
            pe.close()

            with open(file_path, 'rb') as file:
                file.seek(cert_offset)
                global cert_data
                cert_data = file.read(cert_size)
                return True
    except pefile.PEFormatError:
        print(f"Error: '{file_path}' is not a valid PE file.")
        return False
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        pe.close()
        return False


def find_all_exes(directory):
	exe_files = []
	for root, _, files in os.walk(directory):
		for file in files:
			if file.lower().endswith(".exe"):
				exe_files.append(os.path.join(root, file))
	return exe_files

def parse_cert(certificates, file_to_check):
    cert = certificates[0]
    parsed_cert_der = cert.dump()

    parsed_cert = x509.load_der_x509_certificate(parsed_cert_der, default_backend())

    try:
        eku_extension = parsed_cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage)
        eku_oids = eku_extension.value
        eku_purposes = [oid.dotted_string for oid in eku_oids]

        return eku_purposes
    except x509.ExtensionNotFound:
        return None
    except Exception as e:
        print(f"[-] Error parsing certificate file. Details:\n\tFile: {file_to_check}\n\tError: {e}")
        return None

def reset_cert_data():
    global cert_data
    cert_data = ""

# Main
parser = argparse.ArgumentParser(description="Check all EXE binaries in directory for any that can run with PPL privileges")
parser.add_argument("-d", "--directory", type=str, help="Directory to scan (Default: System32)", default="C:\\Windows\\System32")

args = parser.parse_args()

all_exes = find_all_exes(args.directory)
for file_to_check in all_exes:
    if is_digitally_signed(file_to_check):
        cert_data_payload = cert_data[8:]
        signed_data = cms.ContentInfo.load(cert_data_payload)
        signer_certs = signed_data['content']['certificates']
        eku = parse_cert(signer_certs, file_to_check)
        if eku:
            ppl_usage = []
            if "1.3.6.1.4.1.311.10.3.22" in eku:
                ppl_usage.append("Protected Process Light Verification")
            if "1.3.6.1.4.1.311.10.3.23" in eku:
                ppl_usage.append("Windows TCB Component")
            if "1.3.6.1.4.1.311.10.3.24" in eku:
                ppl_usage.append("Protected Process Verification")
            if ppl_usage:
                print(f"\033[92m{file_to_check}\033[0m")
                for usage in ppl_usage:
                    print(f"\t{usage}")
                print("")
