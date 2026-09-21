#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

void eea(mpz_t gcd, mpz_t x, mpz_t y, mpz_t a, mpz_t b);

//given functions
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);

int main(int argc, char *argv[]){
    int numLen = 0;
    int modLen = 0;
    unsigned char *number = Read_File(argv[1], &numLen);
    unsigned char *mod = Read_File(argv[2], &modLen);

    mpz_t a;
    mpz_t b;
    mpz_t gcd;
    mpz_t x;
    mpz_t y;
    mpz_inits(a, b, gcd, x, y, NULL);

    mpz_set_str(a, (char *)number, 10);
    mpz_set_str(b, (char *)mod, 10);

    eea(gcd, x, y, a, b);

    mpz_mod(x, x, b);

    char *result = mpz_get_str(NULL, 10, x);
    Write_File("Result.txt", result);
    printf("%s\n", result);
    free(result);
    free(number);
    free(mod);
    mpz_clears(a, b, gcd, x, y, NULL);

    return 0;
}

void eea(mpz_t gcd, mpz_t x, mpz_t y, mpz_t a, mpz_t b){
    mpz_t r;
    mpz_t oldR;
    mpz_t s;
    mpz_t oldS;
    mpz_t t;
    mpz_t oldT;
    mpz_t q;
    mpz_t tmp;
    mpz_inits(r, oldR, s, oldS, t, oldT, q, tmp, NULL);

    mpz_set(oldR, a);
    mpz_set(r, b);
    mpz_set_ui(oldS, 1);
    mpz_set_ui(s, 0);
    mpz_set_ui(oldT, 0);
    mpz_set_ui(t, 1);

    while(mpz_sgn(r) != 0){
        mpz_fdiv_q(q, oldR, r);

        mpz_mul(tmp, q, r);
        mpz_sub(tmp, oldR, tmp);

        mpz_set(oldR, r);
        mpz_set(r, tmp);

        mpz_mul(tmp, q, s);
        mpz_sub(tmp, oldS, tmp);

        mpz_set(oldS, s);
        mpz_set(s, tmp);

        mpz_mul(tmp, q, t);
        mpz_sub(tmp, oldT, tmp);

        mpz_set(oldT, t);
        mpz_set(t, tmp);
    }
    mpz_set(gcd, oldR);
    mpz_set(x, oldS);
    mpz_set(y, oldT);
    mpz_clears(oldR, r, oldS, s, oldT, t, q, tmp, NULL);
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