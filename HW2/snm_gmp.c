#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>
#include "RequiredFunctionsHW2.h"

void snm(mpz_t Result, mpz_t Base, mpz_t Exponent, mpz_t Modulo) {

    // Initalize Result to 1
    mpz_set_ui(Result,1);
    
    // Size of the exponent in base 2
    size_t k = mpz_sizeinbase(Exponent, 2);

    for(size_t i = k; i > 0; i--) {

        mpz_mul(Result, Result, Result);
        mpz_mod(Result, Result, Modulo);

        // Test if the bits is 1
        if(mpz_tstbit(Exponent, i - 1)) {
            
            mpz_mul(Result, Result, Base);
            mpz_mod(Result, Result, Modulo);

        }
    }
}

int main(int argc, char *argv[]) {

    int BaseLength;
    unsigned char *Base = Read_File(argv[1], &BaseLength);

    int ExpLength;
    unsigned char *Exp = Read_File(argv[2], &ExpLength);

    int ModLength;
    unsigned char *Mod = Read_File(argv[3], &ModLength);

    mpz_t LongBase;
    mpz_init(LongBase);
    mpz_set_str(LongBase, Base, 10);

    mpz_t LongExp;
    mpz_init(LongExp);
    mpz_set_str(LongExp, Exp, 10);

    mpz_t LongMod;
    mpz_init(LongMod);
    mpz_set_str(LongMod, Mod, 10);

    mpz_t Result;
    mpz_init(Result);
    snm(Result, LongBase, LongExp, LongMod);

    char *r = mpz_get_str(NULL, 10, Result);
    Write_File("Result.txt", r);

    return 0;
}