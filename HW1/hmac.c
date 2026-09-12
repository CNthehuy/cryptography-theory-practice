#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>

//Given functions from RequiredFunctionsHW1.c
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Convert_To_Uchar(char* input_hex, unsigned char output[], int output_len);
void Concatenation(unsigned char* in1, size_t in1len, unsigned char* in2, size_t in2len, unsigned char* out, size_t outlen);
unsigned char* Hash_Blake2s(unsigned char* input, unsigned long inputlen);


int main(int argc, char *argv[]){
    int messageLen = 0;
    int keyLen = 0;

    unsigned char *message = Read_File(argv[1], &messageLen);
    unsigned char *key = Read_File(argv[2], &keyLen);

    char *hex = malloc((keyLen * 2) + 1);

    Convert_to_Hex(hex, key, keyLen);
    hex[keyLen * 2] = '\0';

    Write_File("Key.txt", hex);

    unsigned char processKey[64];

    memset(processKey, 0, 64);
    if(keyLen > 64){
        unsigned char *hashKey = Hash_Blake2s(key, keyLen);
        memcpy(processKey, hashKey, 32);
        free(hashKey);
    }else{
        memcpy(processKey, key, keyLen);
    }

    char processKeyHex[(64 * 2) + 1];

    Convert_to_Hex(processKeyHex, processKey, 64);
    processKeyHex[64 * 2] = '\0';

    Write_File("ProcessedKey.txt", processKeyHex);

    unsigned char ipad[64];
    unsigned char opad[64];
    unsigned char xorIpad[64];
    unsigned char xorOpad[64];

    memset(ipad, 0x36, 64);
    memset(opad, 0x5c, 64);

    for(int i = 0; i < 64; i++){
        xorIpad[i] = processKey[i] ^ ipad[i];
        xorOpad[i] = processKey[i] ^ opad[i];
    }

    int inputLen = 64 + messageLen;
    unsigned char *innerInput = malloc(inputLen);

    Concatenation(xorIpad, 64, message, messageLen, innerInput, inputLen);

    unsigned char *innerHash = Hash_Blake2s(innerInput, inputLen);

    int outerInputLen = 96;
    unsigned char *outerInput = malloc(outerInputLen);

    Concatenation(xorOpad, 64, innerHash, 32, outerInput, outerInputLen);

    unsigned char *finalHash = Hash_Blake2s(outerInput, outerInputLen);

    char finalHashHex[(32 * 2) + 1];

    Convert_to_Hex(finalHashHex, finalHash, 32);

    finalHashHex[32 * 2] = '\0';

    Write_File("FinalHash.txt", finalHashHex);

    free(message);
    free(key);
    free(hex);
    free(innerInput);
    free(innerHash);
    free(outerInput);
    free(finalHash);

    return 0;
}

//Given function from RequiredFunctionsHW1.c
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

//Given function from RequiredFunctionsHW1.c
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

//Given function from RequiredFunctionsHW1.c
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
}

//Given function
void Convert_To_Uchar(char* input_hex, unsigned char output[], int output_len)
{   
    for(int i=0; i<output_len; i++){
        unsigned char tmp[2];
        tmp[0]= input_hex[2*i];
        tmp[1]= input_hex[2*i+1];
        output[i] = (unsigned char)strtol(tmp, NULL, 16);
    }
}

//Given function from RequiredFunctionsHW1.c
void Concatenation(unsigned char* in1, size_t in1len, unsigned char* in2, size_t in2len, unsigned char* out, size_t outlen){
    if (in1len + in2len < outlen) {
        printf("Concatenation error: length of output is not enough to fit inputs. Behavior is undefined.\n");
    }
    memcpy(out, in1, in1len);
    memcpy(out+in1len, in2, in2len);
}

//Given function from RequiredFunctionsHW1.c
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