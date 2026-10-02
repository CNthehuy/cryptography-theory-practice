#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

//given macros
#define LENGTH_OF_EACH_MESSAGE 64
#define NUMBER_OF_MESSAGES 4

//given functions
unsigned char* Read_File(char fileName[], int *fileLen);
void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][LENGTH_OF_EACH_MESSAGE], int num);
void Write_Multiple_Lines_to_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE], int num);
void AES256CTR_Encrypt(const unsigned char *key, const unsigned char *input, int input_len, unsigned char *output);
void Convert_to_Hex (char output[], unsigned char input[], int inputlength);
void Write_Ciphertext_to_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE * 2], int num);

int main(int argc, char *argv[]){
    int seedLen = 0;
    unsigned char *sharedSeed = Read_File(argv[1], &seedLen);

    unsigned char messages[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];
    Read_Multiple_Lines_from_File(argv[2], messages, NUMBER_OF_MESSAGES);

    unsigned char key[32];
    unsigned char nextKey[32];
    SHA256(sharedSeed, seedLen, key);

    unsigned char cipherText[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];
    char hexKeys[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE];

    for(int i = 0; i < NUMBER_OF_MESSAGES; i++){
        Convert_to_Hex(hexKeys[i], key, 32);
        AES256CTR_Encrypt(key, messages[i], LENGTH_OF_EACH_MESSAGE, cipherText[i]);
        SHA256(key, 32, nextKey);
        memcpy(key, nextKey, 32);
    }

    Write_Multiple_Lines_to_File("Keys.txt", hexKeys, NUMBER_OF_MESSAGES);

    char hexOutput[NUMBER_OF_MESSAGES][LENGTH_OF_EACH_MESSAGE * 2];
    for(int i = 0; i < NUMBER_OF_MESSAGES; i++){
        Convert_to_Hex(hexOutput[i], cipherText[i], LENGTH_OF_EACH_MESSAGE);
    }

    Write_Ciphertext_to_File("Ciphertexts.txt", hexOutput, NUMBER_OF_MESSAGES);
    
    return 0;
}

//given function
void Read_Multiple_Lines_from_File(char fileName[], unsigned char message[][LENGTH_OF_EACH_MESSAGE], int num)
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

//given function
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    const char hex_digits[] = "0123456789abcdef";
    for (int i = 0; i < inputlength; i++) {
        output[2 * i] = hex_digits[(input[i] >> 4) & 0x0F]; // high nibble
        output[2 * i + 1] = hex_digits[input[i] & 0x0F]; // low nibble
    }
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

//modified copy
void Write_Ciphertext_to_File(char fileName[], char input[][LENGTH_OF_EACH_MESSAGE * 2], int num) { 
    FILE *pFile;
    pFile = fopen(fileName,"w");
    if (pFile == NULL) {
        printf("Error opening file. \n");
        exit(0);
    }
    for(int i=0; i < num; i++) {
        char temp[LENGTH_OF_EACH_MESSAGE * 2 + 1];
        temp[LENGTH_OF_EACH_MESSAGE * 2] = '\0';
        memcpy(temp, input[i], LENGTH_OF_EACH_MESSAGE * 2);
        fputs(temp, pFile);
        
        if (i < (num-1)) fputs("\n", pFile);
    }
    fclose(pFile);
}
