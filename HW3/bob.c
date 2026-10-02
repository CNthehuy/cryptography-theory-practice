#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <unistd.h>

//given macros
#define LENGTH_OF_EACH_MESSAGE 64
#define NUMBER_OF_MESSAGES 4

//given functions
unsigned char* Read_File(char fileName[], int *fileLen);
void Write_Multiple_Lines_to_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE], int num);
void Convert_to_Uchar(char* input_hex, unsigned char output[], int output_len);
void Read_Ciphertexts_from_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE * 2], int num);
void AES256CTR_Decrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output);

int main(int argc, char *argv[]){
    int seedLen = 0;
    unsigned char *sharedSeed = Read_File(argv[1], &seedLen);

    char hexCipher[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE * 2];
    Read_Ciphertexts_from_File(argv[2], hexCipher, NUMBER_OF_MESSAGES);

    unsigned char key[32];
    unsigned char nextKey[32];
    SHA256(sharedSeed, seedLen, key);

    unsigned char cipherText[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];
    unsigned char plainText[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];

    for(int i = 0; i < NUMBER_OF_MESSAGES; i++){
        Convert_to_Uchar(hexCipher[i], cipherText[i], LENGTH_OF_EACH_MESSAGE);
        AES256CTR_Decrypt(key, cipherText[i], LENGTH_OF_EACH_MESSAGE, plainText[i]);
        SHA256(key, 32, nextKey);
        memcpy(key, nextKey, 32);
    }

    Write_Multiple_Lines_to_File("Plaintexts.txt", (char (*)[LENGTH_OF_EACH_MESSAGE])plainText, NUMBER_OF_MESSAGES);

    free(sharedSeed);

    return 0;
}

//given function
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

//given function
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

//given function
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

//given function
void Convert_to_Uchar(char* input_hex, unsigned char output[], int output_len)
{   
    for(int i=0; i<output_len; i++){
        unsigned char tmp[2];
        tmp[0]= input_hex[2*i];
        tmp[1]= input_hex[2*i+1];
        output[i] = (unsigned char)strtol(tmp, NULL, 16);
    }
}

//modified read
void Read_Ciphertexts_from_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE * 2], int num) {
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    ssize_t line_size;

    FILE *fp = fopen(fileName, "r");

    if (!fp) {
        fprintf(stderr, "Error opening file '%s'\n", fileName);
        exit(0);
    }

    line_size = getline(&line_buf, &line_buf_size, fp);

    for (int i = 0; line_size >= 0 && i < num; i++) {

        // Trim newline
        if (line_size > 0 && line_buf[line_size - 1] == '\n')
            line_buf[--line_size] = '\0';

        // Clear the row
        memset(input[i], 0, LENGTH_OF_EACH_MESSAGE * 2);

        // Copy ciphertext hex string into row
        int copy_len =
            line_size < LENGTH_OF_EACH_MESSAGE * 2
            ? line_size
            : LENGTH_OF_EACH_MESSAGE * 2;

        memcpy(input[i], line_buf, copy_len);

        // Read next line
        line_size = getline(&line_buf, &line_buf_size, fp);
    }

    free(line_buf);
    fclose(fp);
}