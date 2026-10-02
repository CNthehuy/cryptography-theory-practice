#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "RequiredFunctionsHW3.h"

//Total of n = 5 shares
#define SHARES 5
//Any k = 3 of the share can reconstruct the key
//Therefore result polynomial degree of  k - 1 = 2
#define MINIMUM_SHARE 3

uint64_t snm(uint64_t Base, uint64_t Exponent, uint64_t Modulo) {

    // Initalize Result to 1
    uint64_t Result = 1;
    Base %= Modulo;
    for (int i = 63; i >= 0; i--) {      
        Result = (Result * Result) % Modulo;                  
        if ((Exponent >> i) & 1)
            Result = (Result * Base) % Modulo;              
    }

    return Result;
}

int main(int argc, char *argv[]) {

    int SecretLength;
    unsigned char *SecretString = Read_File(argv[1], &SecretLength);

    int ModulusLength;
    unsigned char *Modulus = Read_File(argv[2], &ModulusLength);

    uint64_t p = str_to_uint64(Modulus, ModulusLength);
    uint64_t Secret = str_to_uint64(SecretString, SecretLength);

    //Array storing coefficent
    uint64_t Coefficient[MINIMUM_SHARE];
    Coefficient[0] =  Secret;
    srand(time(NULL));

    //Randomly generate k - 1 number of Coefficent 
    for(int i = 1; i < MINIMUM_SHARE; i++) {
        Coefficient[i] = (uint64_t)rand() % p;
    }

    //Generating the results
    for(int i = 1; i <= SHARES; i++) {

        uint64_t temp = Coefficient[0];
        for(int j = 1; j < MINIMUM_SHARE; j++)
            temp = (temp + Coefficient[j] * snm((uint64_t)i, j, p)) % p;

        char Filename[32];
        snprintf(Filename, sizeof Filename, "Share%d.txt", i);
        
        //Save them into different files.
        char Lines[2][LENGTH_OF_EACH_MESSAGE];
        memset(Lines, 0, sizeof Lines);
        snprintf(Lines[0], LENGTH_OF_EACH_MESSAGE, "%d", i);           
        snprintf(Lines[1], LENGTH_OF_EACH_MESSAGE, "%" PRIu64, temp);  
        Write_Multiple_Lines_to_File(Filename, Lines, 2);
    }

    return 0;
}