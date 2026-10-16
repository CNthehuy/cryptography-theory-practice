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
char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);
void Convert_to_Hex(char output[], unsigned char input[], int inputlength);

int main(int argc, char *argv[]){
    int kLen = 0;
    char *kHex = Read_File(argv[3], &kLen);
    
    int messageLen = 0;
    char *message = Read_File(argv[4], &messageLen);

    int pkLen = 0;
    char *pk = Read_File(argv[1], &pkLen);

    BIGNUM *k = NULL;
    BN_hex2bn(&k, kHex);

    EC_KEY *key = EC_KEY_new_by_curve_name(NID_secp192k1);
    const EC_GROUP *group = EC_KEY_get0_group(key);
    const EC_POINT *G = EC_GROUP_get0_generator(group);

    BN_CTX *bnCTX = BN_CTX_new();

    EC_POINT *Y = EC_POINT_new(group);
    EC_POINT *Pm = EC_POINT_new(group);
    EC_POINT *C = EC_POINT_new(group);
    EC_POINT *Cprime = EC_POINT_new(group);
    EC_POINT *D = EC_POINT_new(group);

    EC_POINT_hex2point(group, pk, Y, bnCTX);
    EC_POINT_hex2point(group, message, Pm, bnCTX);

    EC_POINT_mul(group, C, k, NULL, NULL, bnCTX);
    EC_POINT_mul(group, Cprime, NULL, Y, k, bnCTX);
    EC_POINT_add(group, D, Cprime, Pm, bnCTX);

    char *cHex = EC_POINT_point2hex(group, C, POINT_CONVERSION_UNCOMPRESSED, bnCTX);
    char *dHex = EC_POINT_point2hex(group, D, POINT_CONVERSION_UNCOMPRESSED, bnCTX);

    Write_File("C_Hex.txt", cHex);
    Write_File("D_Hex.txt", dHex);
    Write_File("alice_c.txt", cHex);
    Write_File("alice_d.txt", dHex);



    int skLen = 0;
    char *sk = Read_File(argv[2], &skLen);

    BIGNUM *aliceSK = NULL;
    BN_hex2bn(&aliceSK, sk);

    EC_KEY *ecdsaKey = EC_KEY_new_by_curve_name(NID_secp192k1);
    EC_KEY_set_private_key(ecdsaKey, aliceSK);

    int cLen = strlen(cHex);
    int dLen = strlen(dHex);

    char *ciphertext = malloc(cLen + dLen + 1);
    strcpy(ciphertext, cHex);
    strcat(ciphertext, dHex);

    unsigned char hash[32];
    SHA256((unsigned char *)ciphertext, strlen(ciphertext), hash);

    unsigned int sigLen = 0;
    unsigned char *sig = malloc(ECDSA_size(ecdsaKey));
    ECDSA_sign(0, hash, 32, sig, &sigLen, ecdsaKey);

    char *sigHex = malloc(sigLen * 2 + 1);
    Convert_to_Hex(sigHex, sig, sigLen);
    sigHex[sigLen * 2] = '\0';

    Write_File("alice_signature.txt", sigHex);

    free(kHex);
    free(message);
    free(pk);
    free(sk);
    free(ciphertext);
    free(sig);
    free(sigHex);

    OPENSSL_free(cHex);
    OPENSSL_free(dHex);

    BN_free(k);
    BN_free(aliceSK);

    EC_POINT_free(Y);
    EC_POINT_free(Pm);
    EC_POINT_free(C);
    EC_POINT_free(Cprime);
    EC_POINT_free(D);

    BN_CTX_free(bnCTX);

    EC_KEY_free(key);
    EC_KEY_free(ecdsaKey);

    return 0;
}

//given function
char* Read_File (char fileName[], int *fileLen)
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
    char *output = (char*) malloc(temp_size);
	fgets(output, temp_size, pFile);
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
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

//given function
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}

