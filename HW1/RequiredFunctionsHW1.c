/*
*      Homework 1        
*
*Documentation:    SSL Documentation: https://www.openssl.org/docs/manmaster/man3/
*
*   OpenSSL Doc on Blake2: https://docs.openssl.org/master/man7/EVP_MD-BLAKE2/
*   OpenSSL Doc on EVP_Digest: https://docs.openssl.org/master/man3/EVP_DigestInit/
*   OpenSSL Doc on SHA256: https://docs.openssl.org/master/man3/SHA256_Init/
*   OpenSSL Doc on HMAC: https://docs.openssl.org/master/man3/HMAC/
* 
* 
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h> // for memcpy()
#include <openssl/sha.h>    // for SHA256()
#include <openssl/evp.h>
#include <openssl/hmac.h>

//Function prototypes
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
unsigned char* PRNG(unsigned char *seed, size_t seed_len, size_t output_len);
void Show_in_Hex (char name[], unsigned char hex[], int hexlen);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Convert_To_Uchar(char* input_hex, unsigned char output_uchar[], int output_uchar_length);
unsigned char *SHA256(const unsigned char *data, size_t count, unsigned char *md_buf);
unsigned char* Hash_Blake2s(unsigned char* input, unsigned long inputlen);
unsigned char* HMAC_SHA256(const unsigned char *key, int key_n,
                              const unsigned char *data, size_t data_n,
                              unsigned char *result, unsigned int *result_n);

/*

FUNCTIONS

*/

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

/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[]){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  fputs(input, pFile);
  fclose(pFile);
}

/*============================
        PRNG Function 
        (Unused in HW1)
==============================*/
unsigned char* PRNG(unsigned char *seed, size_t seed_len, size_t output_len)
{
    // User-provided seed (must be 32 bytes for ChaCha20)
    if (seed_len != 32) {
        printf("Seed length must be 32 bytes.\n");
        return NULL;
    }

    // Fixed and zeroed iv (16 bytes (4 counter, 12 nonce))
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
        Note: size of output storage best set to (inputlength * 2) + 1 to allow for null terminator by sprintf()
==============================*/
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
}

/*===================================
        Convert from Hex to unsigned char 
=====================================*/
void Convert_To_Uchar(char* input_hex, unsigned char output[], int output_len)
{   
    for(int i=0; i<output_len; i++){
        unsigned char tmp[2];
        tmp[0]= input_hex[2*i];
        tmp[1]= input_hex[2*i+1];
        output[i] = (unsigned char)strtol(tmp, NULL, 16);
    }
}

/*==============================
        Concatenation Fucntion
================================*/
void Concatenation32(unsigned char a[32], unsigned char b[32], unsigned char c[64]){
    memcpy(c, a, 32);
    memcpy(c+32, b, 32);
}

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
    SHA256 Hash Function
==============================*/
/*--- Description:
*   SHA256() computes the SHA-256 message digest of the "count" bytes at data and places it in md_buf.
*   SHA256() returns a pointer to the hash value.
*   md_buf should be array of size SHA256_DIGEST_LENGTH which is typically 32 (constant defined from openssl/sha.h)
*/
unsigned char *SHA256(const unsigned char *data, size_t count, unsigned char *md_buf);

/*============================
        Blake 2s Hash Function
==============================*/

unsigned char* Hash_Blake2s(unsigned char* input, unsigned long inputlen) {
    unsigned char *hash_result = (unsigned char*) malloc(EVP_MAX_MD_SIZE); // malloc the EVP max size, which is 64, setting to 32 or 33 gives intermittent memory errors
    int hash_len; // ends up set to 32 during EVP_DigestFinal, unused
    
    const EVP_MD* md = EVP_get_digestbyname("BLAKE2s256"); // Get the BLAKE2s hashing (digest) algorithm
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new(); // Create the digest context required for next parts
    EVP_DigestInit_ex(mdctx, md, NULL); // Initialize the digest context for hashing with Blake2s
    EVP_DigestUpdate(mdctx, input, inputlen); // Update the digest context with the input to be hashed
    EVP_DigestFinal_ex(mdctx, hash_result, &hash_len); // Finalize the hash computation, putting result in hash_result

    EVP_MD_CTX_free(mdctx);

    return hash_result;
}

/*============================
        HMAC Function using OpenSSL's HMAC() and EVP_sha256() as the hashing function
==============================*/
/*
    Parameters and value types for OpenSSL's HMAC function:
    unsigned char *HMAC(const EVP_MD *evp_md, const void *key, int key_len,
                    const unsigned char *data, size_t data_len,
                    unsigned char *md, unsigned int *md_len);
    Note md_len in the arguments is passed as a pointer, the length of the hash output is put into that variable
*/
unsigned char* HMAC_SHA256(const unsigned char *key, int key_n,
                              const unsigned char *data, size_t data_n,
                              unsigned char *result, unsigned int *result_n) {
    return HMAC(EVP_sha256(), key, key_n, data, data_n, result, result_n);
}

//__________________________________________________________________________________________________________________________
