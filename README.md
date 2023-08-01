# README

# TEAM DES (DAM Embedded Security)

## Running the insecure example

1. Build the firmware by navigating to `firmware/firmware`, and running `make`.
2. Build the bootloader by navigating to `tools`, and running `python bl_build.py`
2. Run the bootloader by navigating to `tools`, and running `python bl_emulate.py`

## Troubleshooting

Ensure that BearSSL is compiled for the stellaris: `cd ~/lib/BearSSL && make CONF=../../stellaris/bearssl/stellaris clean && make CONF=../../stellaris/bearssl/stellaris`

Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
Approved for public release. Distribution unlimited 23-02181-13.

__________________________________________________________
## Used Libraries
- BearSSL
- PyCryptoDome


## bootloader.c

## bl_build.py
- **bl_build.py** is our bootloader building tool.
  - Compile the bootloader.
  - Copy the firmware binary into the bootloader directory
  
It will also create two files 
- **secret_build_output.txt**
  - A 128 bit key for AES-128 encryption
  - A private key to sign data sent through the serial for RSA
- **keys.h**
  - Can be accessed by the Stellaris
  - The same 128 bit key for AES-128 decryption
  - A public key to verify the signature of data sent through the serial
 
## fw_protect.py
- **fw_protect.py** is used to implement (**C**)confidentiality, (**I**)Integrity, and (**A**)authentication.
  - The core feature is to append a version number and release (boot) message to the firmware binary.
- fw_protect.py will take the firmware binary as an input and output the secure version.


## fw_update.py
- **fw_update.py** is responsible for transferring and updating new firmware to the microcontroller.
  - Ensures the device’s software is up-to-date and facilitates the process
  - Also ensures that the buffer doesn’t overflow by sending the data in frames and waiting for the stellaris to receive the sent frame.
- Security
   -Parse the signatures, tags, and metadata from the firmware file.



