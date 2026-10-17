#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>

//given functions
unsigned char* Read_File (char fileName[], int *fileLen);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);
void Write_File(char fileName[], char input[]);

int main(int argc, char *argv[]){
    int seedLen = 0;
    unsigned char *seed = Read_File(argv[1], &seedLen);

    unsigned char secretKey[32];
    SHA256(seed, 32, secretKey);

    char keyHex[32 * 2 + 1];
    Convert_to_Hex(keyHex, secretKey, 32);
    keyHex[64] = '\0';

    BIGNUM *y = NULL;
    BN_hex2bn(&y, keyHex);

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp192k1);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *G = EC_GROUP_get0_generator(group);

    BN_CTX *bnCTX = BN_CTX_new();
    EC_POINT *Y = EC_POINT_new(group);

    EC_POINT_mul(group, Y, NULL, G, y, bnCTX);

    char *pkHex = EC_POINT_point2hex(group, Y, POINT_CONVERSION_UNCOMPRESSED, bnCTX);

    Write_File("SK_Hex.txt", keyHex);
    Write_File("PK_Hex.txt", pkHex);

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
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}

//given function
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
