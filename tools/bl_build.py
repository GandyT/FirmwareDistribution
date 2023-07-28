#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Bootloader Build Tool

This tool is responsible for building the bootloader from source and copying
the build outputs into the host tools directory for programming.
"""
import argparse
import os
import pathlib
import shutil
import subprocess

from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA

REPO_ROOT = pathlib.Path(__file__).parent.parent.absolute()
BOOTLOADER_DIR = os.path.join(REPO_ROOT, "bootloader")

HEADER_FILE = os.path.join(BOOTLOADER_DIR, "src/keys.h")

# generates 
# secret file
# aes key
# rsa private key

def convert_to_array(name, byteString):
    out = ""
    for i in range(len(byteString)):
        if i == len(byteString) - 1:
            out += str(hex(byteString[i]))
        else:
            out += str(hex(byteString[i])) + ", "
    return "const uint8_t " + name + "[" + str(len(byteString)) + "] = " + "{" + out + "};"

def generate_keys():
    aes_key = get_random_bytes(16)

    rsa = RSA.generate(2048)

    rsa_private_key = rsa.export_key("PEM")
    rsa_public_key = rsa.publickey().export_key()

    hmac_key = get_random_bytes(32)

    # write to secrets
    f = open(os.path.join(BOOTLOADER_DIR, "src/secret_build_output.txt"), "wb")
    f.write(aes_key + hmac_key + rsa_private_key)
    f.close()

    # keys.h
    # aes key
    # rsa_public key
    c_aes_key = convert_to_array("aesKey", aes_key)

    rsa_public_key = b"".join(rsa_public_key.split(b"\n"))
    startKey = b"-----BEGIN PUBLIC KEY-----"
    endKey = b"-----END PUBLIC KEY-----"
    rsa_public_key = rsa_public_key[len(startKey):-len(endKey)]

    rsa_public_exponent = rsa_public_key[256:]
    rsa_public_key = rsa_public_key[:256]

    c_rsa_public_key = convert_to_array("rsaModulus", rsa_public_key)

    c_rsa_public_exponent = convert_to_array("rsaExponent", rsa_public_exponent)

    c_hmac_key = convert_to_array("hmacKey", hmac_key)

    keysFile = "#ifndef KEYS_H\n#define KEYS_H\n" + c_aes_key + "\n" + c_rsa_public_key + "\n" + c_rsa_public_exponent + "\n" + c_hmac_key + "\n#endif"
    f = open(HEADER_FILE, "w")
    f.write(keysFile)
        

def copy_initial_firmware(binary_path: str):
    # Copy the initial firmware binary to the bootloader build directory

    os.chdir(os.path.join(REPO_ROOT, "tools"))
    shutil.copy(binary_path, os.path.join(BOOTLOADER_DIR, "src/firmware.bin"))


def make_bootloader() -> bool:
    # Build the bootloader from source.

    os.chdir(BOOTLOADER_DIR)

    subprocess.call("make clean", shell=True)
    status = subprocess.call("make")

    # Return True if make returned 0, otherwise return False.
    return status == 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Bootloader Build Tool")
    parser.add_argument(
        "--initial-firmware",
        help="Path to the the firmware binary.",
        default=os.path.join(REPO_ROOT, "firmware/gcc/main.bin"),
    )
    args = parser.parse_args()
    firmware_path = os.path.abspath(pathlib.Path(args.initial_firmware))

    if not os.path.isfile(firmware_path):
        raise FileNotFoundError(
            f'ERROR: {firmware_path} does not exist or is not a file. You may have to call "make" in the firmware directory.'
        )

    copy_initial_firmware(firmware_path)
    generate_keys()
    make_bootloader()

    # delete header file
    # os.remove(HEADER_FILE)
    

