#ifndef REQUIREDFUNCTIONSHW4_H
#define REQUIREDFUNCTIONSHW4_H
/*

ElGamal and ECDSA
HW4 Required functions


*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <zmq.h>

/*
// BIGNUM functions

// Create context for BIGNUM
BN_CTX *bn_ctx;
bn_ctx = BN_CTX_new();

// BIGNUM to hex conversion
char *BN_bn2hex(const BIGNUM *a);

// Hex to BIGNUM conversion
int BN_hex2bn(BIGNUM **a, const char *str);

// EC POINT functions

// Create EC_POINT and freeing EC_POINT
EC_POINT *EC_POINT_new(const EC_GROUP *group);
void EC_POINT_free(EC_POINT *point);

// Get point conversion from group
point_conversion_form_t EC_GROUP_get_point_conversion_form(const EC_GROUP *group);

// EC_POINT to hex conversion
char *EC_POINT_point2hex(const EC_GROUP *group, const EC_POINT *p, point_conversion_form_t form, BN_CTX *ctx);

// Hex to EC_POINT conversion
EC_POINT *EC_POINT_hex2point(const EC_GROUP *group, const char *hex, EC_POINT *p, BN_CTX *ctx);


// EC Point Multiplication
// EC_POINT_mul calculates the value generator * n + q * m and stores the result in r. 

int EC_POINT_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *n, const EC_POINT *q, const BIGNUM *m, BN_CTX *ctx);

int EC_POINT_add(const EC_GROUP *group, EC_POINT *r, const EC_POINT *a, const EC_POINT *b, BN_CTX *ctx);



// EC_KEY functions

// EC_KEY creation
// A new EC_KEY can be constructed by calling EC_KEY_new_by_curve_name() and supplying the nid of the associated curve

EC_KEY *EC_KEY_new_by_curve_name(int nid);

//For DSA and DH, use the following curve:
eckey_DSA = EC_KEY_new_by_curve_name(NID_secp192k1);
eckey_DH = EC_KEY_new_by_curve_name(NID_secp192k1);

// Get group from EC_KEY
const EC_GROUP *EC_KEY_get0_group(const EC_KEY *key);

// Get the convert_form from EC_KEY
point_conversion_form_t EC_KEY_get_conv_form(const EC_KEY *key);

// EC_KEY set private key
int EC_KEY_set_private_key(EC_KEY *key, const BIGNUM *priv_key);

// EC_KEY set public key
int EC_KEY_set_public_key(EC_KEY *key, const EC_POINT *pub);



// ECDSA

// OpenSSL Website that has example on ECDSA 
// https://www.openssl.org/docs/manmaster/man3/ECDSA_do_sign_ex.html

// SHA256 Hash function
unsigned char *SHA256(const unsigned char *data, size_t count, unsigned char *md_buf);

//ECDSA Signature Size
//ECDSA_size() returns the maximum length of a DER encoded ECDSA signature created with the private EC key eckey
int ECDSA_size(const EC_KEY *eckey);

//ECDSA Signature
int ECDSA_sign(int type, const unsigned char *dgst, int dgstlen, unsigned char *sig, unsigned int *siglen, EC_KEY *eckey);

//ECDSA Verification
int ECDSA_verify(int type, const unsigned char *dgst, int dgstlen, const unsigned char *sig, int siglen, EC_KEY *eckey);

*/

// Other functions

// Read file
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

// Write to file
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

// Show in hex
void Show_in_Hex(char name[], unsigned char hex[], int hexlen)
{
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}

// Convert to hex
void Convert_to_Hex(char output[], unsigned char input[], int inputlength)
{
    for (int i=0; i<inputlength; i++){
        sprintf(&output[2*i], "%02x", input[i]);
    }
    //printf("Hex format: %s\n", output);  //remove later
}

#endif