#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

//given functions
char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);

int main(int argc, char *argv[]) {

    // ---------- Setup ----------

    if (argc != 6) {
        printf("Invalid arguments\n");
        return 1;
    }

    int SKLen, CLen, DLen, SigLen, PKLen;
    char *SK_Hex  = Read_File(argv[1], &SKLen);
    char *PK_Hex  = Read_File(argv[2], &PKLen);
    char *C_Hex   = Read_File(argv[3], &CLen);
    char *D_Hex   = Read_File(argv[4], &DLen);
    char *Sig_Hex = Read_File(argv[5], &SigLen);

    BN_CTX *bn_ctx = BN_CTX_new();
    EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_secp192k1);

    // ---------- ECDSA verification ----------

    // Alice's public key to EC_KEY
    EC_POINT *alicePK = EC_POINT_new(group);
    EC_POINT_hex2point(group, PK_Hex, alicePK, bn_ctx);
    EC_KEY *eckey_DSA = EC_KEY_new_by_curve_name(NID_secp192k1);
    EC_KEY_set_public_key(eckey_DSA, alicePK);

    // H(C||D)
    char *CD = malloc(CLen + DLen + 1);
    strcpy(CD, C_Hex);
    strcat(CD, D_Hex);
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)CD, strlen(CD), hash);

    // Convert hex signature into bytes
    int sigBytesLen = SigLen / 2;
    unsigned char *sig = malloc(sigBytesLen);
    for (int i = 0; i < sigBytesLen; i++) {
        unsigned int b;
        sscanf(&Sig_Hex[2 * i], "%2x", &b);
        sig[i] = (unsigned char)b;
    }

    // If signature invalid, quit without decrypting
    if (ECDSA_verify(0, hash, SHA256_DIGEST_LENGTH, sig, sigBytesLen, eckey_DSA) != 1) {
        printf("Signature invalid.\n");
        return 1;
    }

    // ---------- ElGamal decryption ----------

    BIGNUM *y = NULL;
    BN_hex2bn(&y, SK_Hex);

    EC_POINT *C = EC_POINT_new(group);
    EC_POINT *D = EC_POINT_new(group);
    EC_POINT_hex2point(group, C_Hex, C, bn_ctx);
    EC_POINT_hex2point(group, D_Hex, D, bn_ctx);

    // C' = y.C
    EC_POINT *Cprime = EC_POINT_new(group);
    EC_POINT_mul(group, Cprime, NULL, C, y, bn_ctx);

    // Pm = D - C'
    EC_POINT_invert(group, Cprime, bn_ctx);
    EC_POINT *Pm = EC_POINT_new(group);
    EC_POINT_add(group, Pm, D, Cprime, bn_ctx);

    char *Pm_Hex = EC_POINT_point2hex(group, Pm, EC_GROUP_get_point_conversion_form(group), bn_ctx);
    Write_File("Plaintext.txt", Pm_Hex);

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