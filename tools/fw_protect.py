#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Bundle-and-Protect Tool

"""
import argparse
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from pwn import *
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

def get_bytes(byteString):
    out = "{"

    for i in range(len(byteString)):
        if i == len(byteString) - 1:
            
            out += str(hex(byteString[i]))
        else:

            out += str(hex(byteString[i])) + ", "
    return out + "}"

def generate_bad_private_key():
    rsa = RSA.generate(2048)

    return rsa

def protect_firmware(infile, outfile, version, message):
    # Load firmware binary from infile
    with open(infile, 'rb') as fp:
        firmware = fp.read()

    #obtain key from secret_build_output.txt
    f = open("../bootloader/src/secret_build_output.txt", "rb")
    aes_key = f.read(16)
    HMAC_key = f.read(32)
    rsa_key = f.read()

    f.close()

    private_key = RSA.import_key(rsa_key)
    
    # Pack message, version and size into two little-endian shorts

    firmware_and_message = firmware + message.encode() + b'\00'

    metadata = p16(len(firmware), endian = "little") + p16(version, endian = "little") + p16(len(message.encode())+1, endian = "little")
    
    #create an IV and hash metadata using HMAC
    IV = get_random_bytes(16)
    
    h = HMAC.new(HMAC_key, metadata + IV, digestmod = SHA256)
    MAC_tag = h.digest()
    
    #create a signature for the firmware prior to encryption
    pre_hash = firmware
    hash_func = SHA256.new(pre_hash)
    # bad_private_key = generate_bad_private_key() # used for testing
    signature = pkcs1_15.new(private_key).sign(hash_func)
    
    #Create the random IV and encrypt the firmware with AES in CBC mode
    cipher = AES.new(aes_key, AES.MODE_CBC, iv = IV)

    protectedFirmware = cipher.encrypt(pad(firmware_and_message, AES.block_size))

    # replace metadata with bad metadata for HMAC test
    # metadata = p16(len(firmware), endian = "little") + p16(5, endian = "little") + p16(len(message.encode())+1, endian = "little")
    
    firmware_blob = metadata + IV + MAC_tag + signature + protectedFirmware

    print("IV: " + get_bytes(IV))
    print("HMAC Tag: " + get_bytes(MAC_tag))
    print("RSA Hash Base: " + get_bytes(hash_func.digest()))
    print("RSA Signature: " + get_bytes(signature))

    # Write firmware blob to outfile
    with open(outfile, 'wb+') as outfile: #Original
        outfile.write(firmware_blob) #Original

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Firmware Update Tool')
    parser.add_argument("--infile", help="Path to the firmware image to protect.", required=True)
    parser.add_argument("--outfile", help="Filename for the output firmware.", required=True)
    parser.add_argument("--version", help="Version number of this firmware.", required=True)
    parser.add_argument("--message", help="Release message for this firmware.", required=True)
    args = parser.parse_args()

    protect_firmware(infile=args.infile, outfile=args.outfile, version=int(args.version), message=args.message)