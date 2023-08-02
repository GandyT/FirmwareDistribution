// Copyright 2023 The MITRE Corporation. ALL RIGHTS RESERVED
// Approved for public release. Distribution unlimited 23-02181-13.

// Hardware Imports
#include "inc/hw_memmap.h" // Peripheral Base Addresses
#include "inc/lm3s6965.h"  // Peripheral Bit Masks and Registers
#include "inc/hw_types.h"  // Boolean type
#include "inc/hw_ints.h"   // Interrupt numbers

// Driver API Imports
#include "driverlib/flash.h"     // FLASH API
#include "driverlib/sysctl.h"    // System control API (clock/reset)
#include "driverlib/interrupt.h" // Interrupt API

// Library Imports
#include <string.h>
#include <beaverssl.h>
#include <bearssl.h>

// Application Imports
#include "uart.h"

// keys
#include "keys.h"

// Forward Declarations
void load_initial_firmware(void);
void load_firmware(void);
void boot_firmware(void);
long program_flash(uint32_t, unsigned char *, unsigned int);

// Firmware Constants
#define METADATA_BASE 0xFC00 // base address of version and firmware size in Flash
#define FW_BASE 0x10000      // base address of firmware in Flash

// FLASH Constants
#define FLASH_PAGESIZE 1024
#define FLASH_WRITESIZE 4

// Protocol Constants
#define METADATA_CODE ((unsigned char)0x00)
#define MESSAGE_CODE ((unsigned char) 0x01)
#define SIGNATURE_CODE ((unsigned char) 0x02)
#define OK ((unsigned char)0x03)
#define ERROR ((unsigned char)0x04)
#define FAILED_WRITE ((unsigned char) 0x05)
#define UPDATE ((unsigned char)'U')
#define BOOT ((unsigned char)'B')

#define FRAME_SIZE 128

// Firmware v2 is embedded in bootloader
// Read up on these symbols in the objcopy man page (if you want)!
extern int _binary_firmware_bin_start;
extern int _binary_firmware_bin_size;

// Device metadata
#define fw_version_address METADATA_BASE;
#define fw_size_address (METADATA_BASE + 2);
uint8_t *fw_release_message_address;
void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len);

// Firmware Buffer
// unsigned char data[FLASH_PAGESIZE];

int main(void){

    // A 'reset' on UART0 will re-start this code at the top of main, won't clear flash, but will clean ram.

    // Initialize UART channels
    // 0: Reset
    // 1: Host Connection
    // 2: Debug
    uart_init(UART0);
    uart_init(UART1);
    uart_init(UART2);

    // Enable UART0 interrupt
    IntEnable(INT_UART0);
    IntMasterEnable();

    load_initial_firmware(); // note the short-circuit behavior in this function, it doesn't finish running on reset!

    uart_write_str(UART2, "Welcome to the BWSI Vehicle Update Service!\n");
    uart_write_str(UART2, "Send \"U\" to update, and \"B\" to run the firmware.\n");
    uart_write_str(UART2, "Writing 0x20 to UART0 will reset the device.\n");

    int resp;
    while (1){
        uint32_t instruction = uart_read(UART1, BLOCKING, &resp);
        if (instruction == UPDATE){
            uart_write_str(UART1, "U");
            load_firmware();
            uart_write_str(UART2, "Loaded new firmware.\n");
            nl(UART2);
        }else if (instruction == BOOT){
            uart_write_str(UART1, "B");
            boot_firmware();
        }
    }
}

/*
 * Load initial firmware into flash
 */
void load_initial_firmware(void){

    if (*((uint32_t *)(METADATA_BASE)) != 0xFFFFFFFF){
        /*
         * Default Flash startup state is all FF since. Only load initial
         * firmware when metadata page is all FF. Thus, exit if there has
         * been a reset!
         */
        return;
    }

    // Create buffers for saving the release message
    uint8_t temp_buf[FLASH_PAGESIZE];
    char initial_msg[] = "This is the initial release message.";
    uint16_t msg_len = strlen(initial_msg) + 1;
    uint16_t rem_msg_bytes;

    // Get included initial firmware
    int size = (int)&_binary_firmware_bin_size;
    uint8_t *initial_data = (uint8_t *)&_binary_firmware_bin_start;

    // Set version 2 and install
    uint16_t version = 2;
    uint32_t metadata = (((uint16_t)size & 0xFFFF) << 16) | (version & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    int i;

    for (i = 0; i < size / FLASH_PAGESIZE; i++){
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), initial_data + (i * FLASH_PAGESIZE), FLASH_PAGESIZE);
    }

    /* At end of firmware. Since the last page may be incomplete, we copy the initial
     * release message into the unused space in the last page. If the firmware fully
     * uses the last page, the release message simply is written to a new page.
     */

    uint16_t rem_fw_bytes = size % FLASH_PAGESIZE;
    if (rem_fw_bytes == 0){
        // No firmware left. Just write the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)initial_msg, msg_len);
    }else{
        // Some firmware left. Determine how many bytes of release message can fit
        if (msg_len > (FLASH_PAGESIZE - rem_fw_bytes)){
            rem_msg_bytes = msg_len - (FLASH_PAGESIZE - rem_fw_bytes);
        }else{
            rem_msg_bytes = 0;
        }

        // Copy rest of firmware
        memcpy(temp_buf, initial_data + (i * FLASH_PAGESIZE), rem_fw_bytes);
        // Copy what will fit of the release message
        memcpy(temp_buf + rem_fw_bytes, initial_msg, msg_len - rem_msg_bytes);
        // Program the final firmware and first part of the release message
        program_flash(FW_BASE + (i * FLASH_PAGESIZE), temp_buf, rem_fw_bytes + (msg_len - rem_msg_bytes));

        // If there are more bytes, program them directly from the release message string
        if (rem_msg_bytes > 0){
            // Writing to a new page. Increment pointer
            i++;
            program_flash(FW_BASE + (i * FLASH_PAGESIZE), (uint8_t *)(initial_msg + (msg_len - rem_msg_bytes)), rem_msg_bytes);
        }
    }
}

// Returning the function is not a valid reject, needs to send error
void reject() {
    uart_write(UART1, ERROR);
    SysCtlReset(); // Reset device
    return;
}

/*
 * Load the firmware into flash.
 */
void load_firmware(void){
    /* INT MEMORY ADDRESSES */
    int* int_data = (int*) 0x20002000;
    // int_data[0] == int read

    /* UINT32_T MEMORY ADDRESSES */
    uint32_t* uint32_data = (uint32_t*) 0x20003000;
    // uint32_data[0] == uint32_t rcv
    // uint32_data[1] == uint32_t data_index
    // uint32_data[2] == uint32_t page_addr
    // uint32_data[3] == uint32_t version
    // uint32_data[4] == uint32_t fw_size
    // uint32_data[5] == uint32_t rm_size
    // uint32_data[6] == uint32_t buffer_length

    uint32_data[2] = FW_BASE;

    /* UINT8_T MEMORY ADDRESSES */
    uint8_t* uint8_data = (uint8_t*) 0x20004000;
    // uint8_data[0] == uint8_t msg_type
    uint8_data[0] = 5;

    /* UINT16_T MEMORY ADDRESSES */
    uint16_t** uint16p_data = (uint16_t**) 0x20004600;
    // uint16p_data[0] = uint16_t* fw_ver_ad
    uint16p_data[0] = (uint16_t*) fw_version_address;

    uint16_t* uint16_data = (uint16_t*) 0x20004500;
    // uint16_data[0] = uint16_t old_versoin
    uint16_data[0] = *(uint16p_data[0]);
    

    // 0x20001000 + 256 bytes -> 0x200010FF
    uint8_t* rsa_signature = (uint8_t*) 0x20005000;
    // 0x20001100 + 16 bytes -> 0x2000110F
    uint8_t* iv = (uint8_t*) 0x20005100; 
    // 0x20001110 + 32 bytes -> 0x2000112F
    char* hmac_tag = (char*) 0x20005110;
    // 0x20001130 + 32 bytes -> 0x2000114F
    uint8_t* new_tag = (uint8_t*) 0x20005130;
    // 0x20001150 + 32 bytes -> 0x2000116F
    unsigned char* fw_hash = (unsigned char*) 0x20005150;

    // 0x20001170 + 22 bytes -> 0x20001185
    uint8_t* meta_IV = (uint8_t*) 0x20005170; // the data used to generate the HMAC tag

    // 0x20001186 -> 0x20001585
    unsigned char* data = (unsigned char*) 0x20005186;
    // 0x20001586 + 30kb -> somewhere
    uint8_t* fw_buffer = (uint8_t*) 0x20005586;

    /* GET MSG TYPE (0x1 bytes)*/
    uint32_data[0] = uart_read(UART1, BLOCKING, &int_data[0]);
    uint8_data[0] = (uint8_t) uint32_data[0];

    uart_write_str(UART2, "Received Message Type: ");
    uart_write_hex(UART2, uint32_data[3]);
    nl(UART2);

    /* CHECK IF MSG TYPE IS 0 */
    if (uint8_data[0] != METADATA_CODE) {
        reject();
        return;
    }

     /* GET FW_SIZE (0x2 bytes) */
    uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
    uint32_data[4] = (uint32_t)uint32_data[0];
    uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
    uint32_data[4] |= (uint32_t)uint32_data[0] << 8;

    uart_write_str(UART2, "Received Firmware Size: ");
    uart_write_hex(UART2, uint32_data[4]);
    nl(UART2);

    // Get version as (0x2) bytes 
    uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
    uint32_data[3] = (uint32_t)uint32_data[0];
    uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
    uint32_data[3] |= (uint32_t)uint32_data[0] << 8;

    uart_write_str(UART2, "Received Firmware Version: ");
    uart_write_hex(UART2, uint32_data[3]);
    nl(UART2);

    /* GET RELEASE_MESSAGE_SIZE (0x2 bytes) */
    uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
    uint32_data[5] = (uint32_t)uint32_data[0];
    uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
    uint32_data[5] |= (uint32_t)uint32_data[0] << 8;

    // Compare to old version and abort if older (note special case for version 0).
    if (uint32_data[3] != 0 && uint32_data[3] < uint16_data[0]){
        reject();
        return;
    }

    int debug = 0;
    if (uint32_data[3] == 0){
        // If debug firmware, don't change version
        uint32_data[3] = uint16_data[0];
        debug = 1;
    }

    // Write new firmware size and version to Flash
    // Create 32 bit word for flash programming, version is at lower address, size is at higher address
    uint32_t metadata = ((uint32_data[4] & 0xFFFF) << 16) | (uint32_data[3] & 0xFFFF);
    program_flash(METADATA_BASE, (uint8_t *)(&metadata), 4);

    if (debug) {
        uint32_data[3] = 0; // set version back to 0 after writing
    }

    uart_write(UART1, OK); // Acknowledge the metadata.
    
    uint32_data[6] = (uint32_data[5] + uint32_data[4]) + (16 - ((uint32_data[5] + uint32_data[4]) % 16));

    /* GET IV (0x10 bytes) */
    for (int i = 0; i < 16; i++) {
        uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
        iv[i] = (uint8_t) uint32_data[0];
    }

    /* GET HMAC TAG (0x20 bytes) */
    for (int i = 0; i < 32; i++) {
        uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
        hmac_tag[i] = (char) uint32_data[0];
    }

    /* add shorts */
    meta_IV[0] = (uint8_t) (uint32_data[4]); // fw_size
    meta_IV[1] = (uint8_t) (uint32_data[4] >> 8);
    meta_IV[2] = (uint8_t) (uint32_data[3]);
    meta_IV[3] = (uint8_t) (uint32_data[3] >> 8);
    meta_IV[4] = (uint8_t) (uint32_data[5]);
    meta_IV[5] = (uint8_t) (uint32_data[5] >> 8);

    /* ADD TAGS */
    for (int i = 0; i < 16; ++i) {
        meta_IV[6+i] = iv[i];
    }

    //Create array for new hmac_tag based on data
    
    sha_hmac((char*) hmacKey, 32, (char*) meta_IV, 22, (char*) new_tag);
    
    //Verify the new tag with the old tag
    int same = 1;
    for (int i = 0; i < 32; i++){
        if(new_tag[i] != hmac_tag[i]){
            same = 0;
            break;
        }
    }

    if (same == 0){
        reject();
        return;
    }

    // manually set address of fw_buffer as not doing it manually overwrites the pointer to the pointer of the metadata
    
    int fw_buffer_index = 0;

    /* KEEP READING CHUNKS OF 256 BYTES + SEND OK */
    while (1) {
        /* WAIT FOR MESSAGE TYPE 1 */
        uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
        uint8_data[0] = (uint8_t) uint32_data[0];

        uart_write_str(UART2, "Received Message Type: ");
        uart_write_hex(UART2, uint8_data[0]);
        nl(UART2);
        
        if (uint8_data[0] != MESSAGE_CODE) {
            
            if (uint8_data[0] == SIGNATURE_CODE) break;

            reject();
            return;
        }

        for (int i = 0; i < FRAME_SIZE; ++i) {
            uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
            
            if (fw_buffer_index < uint32_data[6]) {
                fw_buffer[fw_buffer_index] = (uint8_t) uint32_data[0];
                fw_buffer_index += 1;
            }
        }

        uart_write(UART1, OK);
    }

    /* MESSAGE TYPE 2 (RSA SIG) ALREADY READ */
    uart_write_str(UART2, "Received Message Type: ");
    uart_write_hex(UART2, uint8_data[0]);
    nl(UART2);

    /* READ 256 BYTES RSA SIGNATURE */
    for (int i = 0; i < 256; i++) {
        uint32_data[0] = uart_read(UART1, BLOCKING, int_data);
        rsa_signature[i] = (uint8_t)uint32_data[0];
    }
    uart_write_str(UART2, "Received RSA Signature: ");
    nl(UART2);
    uart_write(UART1, OK);

    // decrypt
    aes_decrypt((char*) aesKey, (char*) iv, (char*) fw_buffer, uint32_data[6]);

    sha_hash((unsigned char*) fw_buffer, uint32_data[4], fw_hash);

    br_rsa_public_key pub_key;
    pub_key.n = rsaModulus;
    pub_key.nlen = sizeof(rsaModulus);
    pub_key.e = rsaExponent;
    pub_key.elen = sizeof(rsaExponent);
    
    int result = br_rsa_i15_pkcs1_vrfy(
        rsa_signature, // const unsigned char *x - (signature buffer)
        sizeof(rsa_signature), // size_t xlen - (signature length in bytes)
        BR_HASH_OID_SHA256, // const unsigned char *hash_oid - (OID of hash)
        sizeof(fw_hash), // expected hash value length - (in bytes).
        &pub_key, // const br_rsa_public_key *pk - RSA public key.
        fw_hash // unsigned char *hash_out - output buffer for the hash value
    );

    /*

    if (result == 0){
        reject();
        return;
    }
    */

    uint32_data[6] = uint32_data[4] + uint32_data[5];
    fw_buffer_index = 0;

    uint8_t completed = 0; // set to 1 if read all bytes from buffer

    while (1){
        for (int i = 0; i < FLASH_PAGESIZE; ++i){
            if (fw_buffer_index >= uint32_data[6]) {
                completed = 1;
                break;
            }

            data[uint32_data[1]] = fw_buffer[fw_buffer_index];
            fw_buffer_index += 1;
            uint32_data[1] += 1;
        } // for

        // If we filed our page buffer, program it
        if (uint32_data[1] == FLASH_PAGESIZE || completed == 1){

            if(completed == 1){
                uart_write_str(UART2, "Finished reading data from buffer\n");
            }
            
            // Try to write flash and check for error
            if (program_flash(uint32_data[2], data, uint32_data[1])){
                reject();
                return;
            }

            // Verify flash program
            if (memcmp(data, (void *) uint32_data[2], uint32_data[1]) != 0){
                uart_write_str(UART2, "Flash check failed.\n");
                uart_write(UART1, FAILED_WRITE);
                SysCtlReset(); // Reset device
                return;
            }

            // Write debugging messages to UART2.
            uart_write_str(UART2, "Page successfully programmed\nAddress: ");
            uart_write_hex(UART2, uint32_data[2]);
            uart_write_str(UART2, "\nBytes: ");
            uart_write_hex(UART2, uint32_data[1]);
            nl(UART2);

            // Update to next page
            uint32_data[2] += FLASH_PAGESIZE;
            uint32_data[1] = 0;

            // If at end of firmware, go to main
            if (completed == 1){
                uart_write(UART1, OK);
                break;
            }
        }
    }                          

}

/*
 * Program a stream of bytes to the flash.
 * This function takes the starting address of a 1KB page, a pointer to the
 * data to write, and the number of byets to write.
 *
 * This functions performs an erase of the specified flash page before writing
 * the data.
 */
long program_flash(uint32_t page_addr, unsigned char *data, unsigned int data_len){
    uint32_t word = 0;
    int ret;
    int i;

    // Erase next FLASH page
    FlashErase(page_addr);

    // Clear potentially unused bytes in last word
    // If data not a multiple of 4 (word size), program up to the last word
    // Then create temporary variable to create a full last word
    if (data_len % FLASH_WRITESIZE){
        // Get number of unused bytes
        int rem = data_len % FLASH_WRITESIZE;
        int num_full_bytes = data_len - rem;

        // Program up to the last word
        ret = FlashProgram((unsigned long *)data, page_addr, num_full_bytes);
        if (ret != 0){
            return ret;
        }

        // Create last word variable -- fill unused with 0xFF
        for (i = 0; i < rem; i++){
            word = (word >> 8) | (data[num_full_bytes + i] << 24); // Essentially a shift register from MSB->LSB
        }
        for (i = i; i < 4; i++){
            word = (word >> 8) | 0xFF000000;
        }

        // Program word
        return FlashProgram(&word, page_addr + num_full_bytes, 4);
    }else{
        // Write full buffer of 4-byte words
        return FlashProgram((unsigned long *)data, page_addr, data_len);
    }
}

void boot_firmware(void){
    // compute the release message address, and then print it
    uint16_t *fw_siz_ad = (uint16_t*) fw_size_address;
    uint16_t fw_size = *fw_siz_ad;
    fw_release_message_address = (uint8_t *)(FW_BASE + fw_size);
    uart_write_str(UART2, (char *)fw_release_message_address);

    // Boot the firmware
    __asm(
        "LDR R0,=0x10001\n\t"
        "BX R0\n\t");
}

void uart_write_hex_bytes(uint8_t uart, uint8_t * start, uint32_t len) {
    for (uint8_t * cursor = start; cursor < (start + len); cursor += 1) {
        uint8_t data = *((uint8_t *)cursor);
        uint8_t right_nibble = data & 0xF;
        uint8_t left_nibble = (data >> 4) & 0xF;
        char byte_str[3];
        if (right_nibble > 9) {
            right_nibble += 0x37;
        } else {
            right_nibble += 0x30;
        }
        byte_str[1] = right_nibble;
        if (left_nibble > 9) {
            left_nibble += 0x37;
        } else {
            left_nibble += 0x30;
        }
        byte_str[0] = left_nibble;
        byte_str[2] = '\0';
        
        uart_write_str(uart, byte_str);
        uart_write_str(uart, " ");
    }
}
