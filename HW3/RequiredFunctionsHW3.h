#ifndef REQUIREDFUNCTIONSHW3_H
#define REQUIREDFUNCTIONSHW3_H


/**************************
 *      Homework 3        *
 **************************
 *
 *Documentation:    SSL Documentation: https://www.openssl.org/docs/manmaster/man3/
 *
 *   OpenSSL Doc on EVP_Digest: https://docs.openssl.org/master/man3/EVP_DigestInit/
 *   OpenSSL Doc on SHA256: https://docs.openssl.org/master/man3/SHA256_Init/
 *   OpenSSL Doc on EVP_EncryptInit, EncryptUpdate: https://docs.openssl.org/3.0/man3/EVP_EncryptInit/
 *
_______________________________________________________________________________*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h> // for uint64_t
#include <string.h> // for memcpy()
#include <unistd.h> // for ssize_t
#include <openssl/sha.h>    // for SHA256()
#include <openssl/evp.h> 

// maximum size of each line that Read/Write_multiple_lines() works with
#define LENGTH_OF_EACH_MESSAGE 64
// number of messages per file in ChainCrypt
#define NUMBER_OF_MESSAGES 4
// number of shares generated in Shamir
#define N_SHARES 5
// minimum number of shares needed to reconstruct secret in Shamir
#define THRESHOLD 3

/*  Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][LENGTH_OF_EACH_MESSAGE], int num);
void Write_File(char fileName[], char input[]);
void Write_Multiple_Lines_to_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE], int num);
unsigned char* PRNG(unsigned char *seed, size_t seed_len, size_t output_len);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Convert_To_Uchar(char* input_hex, unsigned char output_uchar[], int output_uchar_length);
unsigned char *SHA256(const unsigned char *data, size_t count, unsigned char *md_buf);
void AES128ECB_Encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output);
void AES256CTR_Encrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output);
void AES256CTR_Decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output);
*/

/*************************************************************
					F u n c t i o n s
**************************************************************/

/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}

/*=======================================
        Read Multiple Lines from File
========================================*/
//*** This function has a fixed output length (LENGTH_OF_EACH_MESSAGE) 
//*** and takes the number of lines to read as an argument (ensure that array is of sufficient size)
//*** If necessary, change the output length accordingly (it can read lengths smaller than the specified size just fine)
/*void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][LENGTH_OF_EACH_MESSAGE], int num)
{
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    int line_count = 0;
    ssize_t line_size;
    FILE *fp = fopen(fileName, "r");
    if (!fp)
        fprintf(stderr, "Error opening file '%s'\n", fileName);

    line_size = getline(&line_buf, &line_buf_size, fp);
    for(int j=0; line_size >= 0 && j < num; j++)
    {
        // Trim newline
        if (line_size > 0 && line_buf[line_size-1] == '\n')
            line_buf[--line_size] = '\0';

        memset(message[j], 0, LENGTH_OF_EACH_MESSAGE);

        // Copy up to LENGTH_OF_EACH_MESSAGE or line_size, whichever is smaller
        int copy_len = line_size < LENGTH_OF_EACH_MESSAGE ? line_size : LENGTH_OF_EACH_MESSAGE;
        memcpy(message[j], line_buf, copy_len);

        // Debug print, set print format length (*) to max LENGTH_OF_EACH_MESSAGE otherwise printf overruns with strings missing null terminator (which is most of the time) 
        printf("Message%d (%ld) == %.*s\n", j+1, line_size, LENGTH_OF_EACH_MESSAGE, message[j]);

        line_size = getline(&line_buf, &line_buf_size, fp);
    }

    free(line_buf);
    fclose(fp);
}
*/
/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[]) {
    FILE *pFile;
    pFile = fopen(fileName,"w");
    if (pFile == NULL){
        printf("Error opening file. \n");
        exit(0);
    }
    fputs(input, pFile);
    fclose(pFile);
}

/*============================================s
        Write Multiple Lines to File
==============================================*/
//*** This function has a fixed input length (LENGTH_OF_EACH_MESSAGE) and takes the number of lines to write as an argument
//*** If necessary, change the input size accordingly (for lines smaller than LENGTH_OF_EACH_MESSAGE, fputs relies on the null terminator to know where EOL is)
//*** If you want to write "unsigned char" into a file, change the format of 'input' and 'temp' to unsinged char (or just cast it on call)
void Write_Multiple_Lines_to_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE], int num) { 
    FILE *pFile;
    pFile = fopen(fileName,"w");
    if (pFile == NULL) {
        printf("Error opening file. \n");
        exit(0);
    }
    for(int i=0; i < num; i++) {
        char temp[LENGTH_OF_EACH_MESSAGE+1];
        temp[LENGTH_OF_EACH_MESSAGE] = '\0';
        memcpy(temp, input[i], LENGTH_OF_EACH_MESSAGE);
        fputs(temp, pFile);
        
        if (i < (num-1)) fputs("\n", pFile);
    }
    fclose(pFile);
}

/*============================
        PRNG Function 
        (Unused)
==============================*/
unsigned char* PRNG(unsigned char *seed, size_t seed_len, size_t output_len)
{
    // User-provided seed (must be 32 bytes for ChaCha20)
    if (seed_len != 32) {
        printf("Seed length must be 32 bytes.\n");
        return NULL;
    }

    // Fixed and zeroed iv (16 bytes (4 counter, 12 nonce)) for deterministic but cryptographically weaker output
    unsigned char iv[16] = {0};

    // Output buffer
    unsigned char* output = malloc(output_len + 1); // +1 for possible null terminator
    unsigned char plaintext[output_len];
    memset(plaintext, 0, sizeof(plaintext));  // Encrypting zeros

    // Initialize ChaCha20 context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context.\n");
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to initialize cipher.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Set seed and nonce
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, seed, iv) != 1) {
        fprintf(stderr, "Failed to set key and nonce.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Encrypt (in the context of chacha20, simply XORs plaintext with keystream, and since plaintext is zeroes, result is just keystream)
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, output, &outlen, plaintext, sizeof(plaintext)) != 1) {
        fprintf(stderr, "Encryption failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);

    return output;
}

/*============================
        Showing in Hex 
==============================*/
void Show_in_Hex (char name[], unsigned char input[], int inputlen)
{
	printf("%s %d: ", name, inputlen);
	for (int i = 0 ; i < inputlen ; i++)
   		printf("%02x", input[i]);
	printf("\n");
}

/*============================
        Convert to Hex 
        Note: make sure output array size is double the size of input
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < inputlength; i++) {
        output[2 * i] = hex_digits[(input[i] >> 4) & 0x0F]; // high nibble
        output[2 * i + 1] = hex_digits[input[i] & 0x0F]; // low nibble
    }
}

/*===================================
        Convert from Hex to unsigned char 
=====================================*/
void Convert_to_Uchar(char* input_hex, unsigned char output[], int output_len)
{   
    for(int i=0; i<output_len; i++){
        unsigned char tmp[2];
        tmp[0]= input_hex[2*i];
        tmp[1]= input_hex[2*i+1];
        output[i] = (unsigned char)strtol(tmp, NULL, 16);
    }
}

// Convert decimal string to uint64_t
uint64_t str_to_uint64(const unsigned char *str, int str_len) {
    uint64_t result = 0;
    int negative = 0;
    if (*str == '-') {
        negative = 1;
        str++;
    }
    for (int i=0; i < str_len && *str >= '0' && *str <= '9'; i++) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return negative ? -result : result;
}

// Convert uint64_t to decimal string
// Note: ensure that output array size is large enough including the null terminator at the end
void uint64_to_str(uint64_t value, unsigned char *output, int output_len) {
    int negative = value < 0;
    if (negative) 
        value = -value;

    // Not going to need more than 10 digits, make it 15 just to be safe
    char temp[15];
    int i = 0;

    // In reverse order, reversed at the end
    do {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    } while (value > 0 && i < (int)sizeof(temp) - 1);

    if (negative) 
        temp[i++] = '-';

    if (i >= output_len) {
        output[0] = '\0';  // Not enough space
        return;
    }

    // Reverse the string into the output
    for (int j = 0; j < i; j++) {
        output[j] = temp[i - j - 1];
    }
    // Null-terminate
    output[i] = '\0';
}

/*==============================
        Concatenation Fucntion
================================*/
/*
    'in1' is a pointer to unsigned char array of length 'in1len', for the left part to be concatenated
    'in2' is a pointer to unsigned char array of length 'in2len', for the right part to be concatenated
    'out' is a pointer to unsigned char array of length 'outlen', for the place to put the concatenated result into
*/
void Concatenation(unsigned char* in1, size_t in1len, unsigned char* in2, size_t in2len, unsigned char* out, size_t outlen){
    if (in1len + in2len < outlen) {
        printf("Concatenation error: length of output is not enough to fit inputs. Behavior is undefined.\n");
    }
    memcpy(out, in1, in1len);
    memcpy(out+in1len, in2, in2len);
}

/*============================
    SHA256 Hash Function (from OpenSSL)
==============================*/
/*--- Description:
*   SHA256() computes the SHA-256 message digest of the "count" bytes at data and places it in md_buf.
*   SHA256() returns a pointer to the hash value.
*   md_buf should be array of size SHA256_DIGEST_LENGTH which is typically 32 (constant defined from openssl/sha.h)
*/
unsigned char *SHA256(const unsigned char *data, size_t count, unsigned char *md_buf);


/*==================================
    AES-128 ECB Encryption Function
====================================*/
/*--- Description:
*   Function uses AES-128 (so 128-bit input, 128-bit output, and 128-bit key)
*       ECB, so no chaining or IV, sufficient for a toy implementation
*       Explicitly set no padding, so input must be 16 bytes exactly
*/
void AES128ECB_Encrypt(const unsigned char *key, const unsigned char *input, unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int outlen;

    EVP_EncryptInit_ex2(ctx, EVP_aes_128_ecb(), key, NULL, NULL);
    EVP_CIPHER_CTX_set_padding(ctx, 0);  // Disable padding

    EVP_EncryptUpdate(ctx, output, &outlen, input, 16);

    EVP_CIPHER_CTX_free(ctx);
}

/*==================================
    AES-256 CTR Encryption and Decryption Functions
====================================*/
/*--- Description:
*   Function uses AES-256 (so 256-bit (32-byte) key)
*   Counter mode allows for any size input, with output same size as input
*   Explicitly set IV to keep the functions deterministic
*   Automatically pads input to block size
*/
void AES256CTR_Encrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    unsigned char iv[16] = "1234567890uvwxyz";

    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, output, &len, input, input_len);

    EVP_EncryptFinal_ex(ctx, output + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return;
}

void AES256CTR_Decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int len;
    unsigned char iv[16] = "1234567890uvwxyz";

    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv);
    EVP_DecryptUpdate(ctx, output, &len, input, input_len);

    EVP_DecryptFinal_ex(ctx, output + len, &len);

    EVP_CIPHER_CTX_free(ctx);
    return;
}


//__________________________________________________________________________________________________________________________

#endif
