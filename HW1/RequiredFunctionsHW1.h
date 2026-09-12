#ifndef REQUIREDFUNCTIONSHW1_H
#define REQUIREDFUNCTIONSHW1_H
#include <stddef.h>

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
void Concatenation32(unsigned char a[32], unsigned char b[32],
                     unsigned char c[64]);

void Concatenation(unsigned char* in1, size_t in1len,
                   unsigned char* in2, size_t in2len,
                   unsigned char* out, size_t outlen);

#endif