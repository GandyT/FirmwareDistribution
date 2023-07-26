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

RESP_OK = p16(3, endian = "little")
FRAME_SIZE = 256

print(RESP_OK)
def send_metadata(ser, metadata, debug=False):
    message_len, version, size = struct.unpack_from("<HHH", metadata[:6])
    print(f"Message Length: {message_len}\nVersion: {version}\nSize: {size} bytes\n")

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
    message_type = p16(0, endian = "little")
    ser.write(message_type + metadata)
    
    # Wait for an OK from the bootloader.
    resp = ser.read(2)

    
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))


def send_frame(ser, frame, debug=False):
    ser.write(frame)  # Write the frame...

    if debug:
        print_hex(frame)

    #ok message is a little endian short so should be 2 bytes
    resp = ser.read(2)  # Wait for an OK from the bootloader

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    if debug:
        print("Resp: {}".format(ord(resp)))

def send_signature(ser, signature, debug=False):
    message_type = p16(2, endian = "little")
    ser.write(message_type + signature)

    if debug:
        print(message_type + "\n" + signature)

    resp = ser.read(2)

    time.sleep(0.1)

    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded with {}".format(repr(resp)))

    

def update(ser, infile, debug):
    # Open serial port. Set baudrate to 115200. Set timeout to 2 seconds.
    with open(infile, "rb") as fp:
        firmware_blob = fp.read()

    # print(firmware_blob)
    metadata_IV_tag = firmware_blob[:54]
    message_size = u16(firmware_blob[:2], endian = "little")
    signature = firmware_blob[54: 310]
    firmware_message = firmware_blob[310:len(firmware_blob) - message_size]
    send_metadata(ser, metadata_IV_tag, debug=debug)

    for idx, frame_start in enumerate(range(0, len(firmware_message), FRAME_SIZE)):
        data = firmware_message[frame_start : frame_start + FRAME_SIZE]

        # Get length of data.
        # length = len(data)
        if len(data) < 256:
            data = pad(data, 256)
        frame_fmt = ">H{}s".format(256)

        #new frame construction with new bootloader
        message_type = p16(1, endian = "little")
        frame = message_type + struct.pack(frame_fmt, 256, data)

        send_frame(ser, frame, debug=debug)
        print(f"Wrote frame {idx} ({len(frame)} bytes)")

    print("Done writing firmware.")

    #send signature to bootloader
    send_signature(ser, signature, debug=debug)
    
    print("Done writing signature.")
    
    # Send a zero length payload to tell the bootlader to finish writing it's page.
    ser.write(struct.pack(">H", 0x0000))
    resp = ser.read(2)  # Wait for an OK from the bootloader
    if resp != RESP_OK:
        raise RuntimeError("ERROR: Bootloader responded to zero length frame with {}".format(repr(resp)))
    print(f"Wrote zero length frame (2 bytes)")

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
