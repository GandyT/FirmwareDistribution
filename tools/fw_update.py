#!/usr/bin/env python

# Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
# Approved for public release. Distribution unlimited 23-02181-13.

"""
Firmware Updater Tool

A frame consists of two sections:
1. Two bytes for the length of the data section
2. A data section of length defined in the length section

[ 0x02 ]  [ variable ]
--------------------
| Length | Data... |
--------------------

In our case, the data is from one line of the Intel Hex formated .hex file

We write a frame to the bootloader, then wait for it to respond with an
OK message so we can write the next frame. The OK message in this case is
just a zero
"""

import argparse
import struct
import time
import socket

from util import *
from pwn import *

from Crypto.Util.Padding import pad

RESP_METADATA = p8(0, endian="little")
RESP_MESSAGE = p8(1, endian="little")
RESP_SIGNATURE = p8(2, endian="little")
RESP_OK = p8(3, endian="little")
ZERO_BYTE = p8(0, endian="little")
FRAME_SIZE = 256

def get_bytes(byteString):
    out = "{"

    for i in range(len(byteString)):
        if i == len(byteString) - 1:
            
            out += str(byteString[i])
        else:

            out += str(byteString[i]) + ", "
    return out + "}"

def send_metadata(ser, metadata, debug=False):
    fw_size = u16(metadata[:2], endian = "little")
    version = u16(metadata[2:4], endian = "little")
    rm_size = u16(metadata[4:6], endian = "little")
    
    print(f"fw_size: {fw_size}\nVersion: {version}\nrm_size: {rm_size} bytes\n")
    
    # Handshake for update
    ser.write(b"U")

    print("Waiting for bootloader to enter update mode...")
    while ser.read(1).decode() != "U":
        print("got a byte")
        pass

    # Send size and version to bootloader.
    if debug:
        print(metadata)

    # ser.write(metadata[2:]) #temporary without bootloader
    #send complete BEGIN frame
    message_type = RESP_METADATA
    packed_metadata = b""

    for byte in metadata:
        packed_metadata += p8(byte, endian="little")

    ser.write(message_type + packed_metadata)
    
    # Wait for an OK from the bootloader.
    resp = ser.read(1)
    
    time.sleep(0.1)
    
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)

    resp = ser.read(1)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))

def send_signature(ser, signature, debug=False):
    message_type = RESP_SIGNATURE
    packed_signature = b""

    for byte in signature:
        packed_signature += p8(byte, endian="little")

    ser.write(message_type + packed_signature)

    if debug:
        print(message_type)
        print(packed_signature)

    resp = ser.read(1)

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    

def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    # print(firmware_blob)
    metadata_IV_tag = firmware_blob[:54]
    rm_size = u16(firmware_blob[4:6], endian = "little")
    signature = firmware_blob[54: 310]

    firmware_message = firmware_blob[310:]
    send_metadata(ser, metadata_IV_tag, debug=debug)

    for idx, frame_start in enumerate(range(0, len(firmware_message), FRAME_SIZE)):
        data = firmware_message[frame_start : frame_start + FRAME_SIZE]

        # Get length of data.
        # length = len(data)
        if len(data) < FRAME_SIZE:
            data = pad(data, FRAME_SIZE)

        #new frame construction with new bootloader
        packed_data = b""
        for byte in data:
            packed_data += p8(byte, endian="little")
        
        frame = RESP_MESSAGE + data

        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx} ({len(frame)} bytes)")

    print("Done writing firmware.")

    #send signature to bootloader
    send_signature(ser, signature, debug=debug)
    
    print("Done writing signature.")
    
    resp = ser.read(1)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Finished Updating...")

    return ser

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Firmware Update Tool")

    parser.add_argument("--port", help="Does nothing, included to adhere to command examples in rule doc", required=False)
    parser.add_argument("--firmware", help="Path to firmware image to load.", required=False)
    parser.add_argument("--debug", help="Enable debugging messages.", action="store_true")
    args = parser.parse_args()

    uart0_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart0_sock.connect(UART0_PATH)

    time.sleep(0.2)  # QEMU takes a moment to open the next socket

    uart1_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart1_sock.connect(UART1_PATH)
    uart1 = DomainSocketSerial(uart1_sock)

    time.sleep(0.2)

    uart2_sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    uart2_sock.connect(UART2_PATH)

    # Close unused UARTs (if we leave these open it will hang)
    uart2_sock.close()
    uart0_sock.close()

    update(ser=uart1, infile=args.firmware, debug=args.debug)

    uart1_sock.close()