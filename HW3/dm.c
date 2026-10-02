
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RequiredFunctionsHW3.h"

int main(int argc, char * argv[]) {

    if(argc < 2) {

        printf("Missing message file");
        return 1;

    }

    int MessageLength;
    unsigned char *Message = Read_File(argv[1], &MessageLength);
    unsigned char Prev[16] = {0};
    char Hex_hash[2 * 16 + 1];

    //DM Compression function
    for(int i = 0; i < MessageLength; i += 16) {

        // Initializing block
        unsigned char block[16] = {0};

        //Verify if there is 16 byte in the remaining message
        int remain = MessageLength - i;
        int block_size = 16;
        if (remain < 16) block_size = remain;

        // Finalize declaring block
        memcpy(block, Message + i, block_size);
        
        //Computing Hash of the block
        unsigned char Hash[16];
        AES128ECB_Encrypt(block, Prev, Hash);
        
        //Xor AES result and Key
        for(int j = 0; j < 16; j++) {
            Prev[j] = Hash[j] ^ Prev[j];
        }

        //Convert result to Hex string format
        Convert_to_Hex(Hex_hash, Prev, 16);
        Hex_hash[32] = '\0';

        // If Fflag = 0, then write result of first hash in hex string format
        if(i == 0) {
            Write_File("FirstHash.txt", Hex_hash);
        }
        if(MessageLength <= i + 16) {
            Write_File("FinalHash.txt", Hex_hash);
        }

    }

    free(Message);
    return 0;
}