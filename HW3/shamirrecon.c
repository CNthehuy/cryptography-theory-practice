#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include "RequiredFunctionsHW3.h"

#define SHARES N_SHARES
#define MINIMUM_SHARE THRESHOLD

uint64_t snm(uint64_t Base, uint64_t Exponent, uint64_t Modulo) {
    uint64_t Result = 1;
    Base %= Modulo;
    for (int i = 63; i >= 0; i--) {
        Result = (Result * Result) % Modulo;
        if ((Exponent >> i) & 1)
            Result = (Result * Base) % Modulo;
    }
    return Result;
}

//Modular inverse via Fermat's little theorem
uint64_t modinv(uint64_t a, uint64_t p) {
    return snm(a, p - 2, p);
}

int main(int argc, char *argv[]) {

    int ModLength;
    unsigned char *Mod = Read_File(argv[1], &ModLength);
    uint64_t p = str_to_uint64(Mod, ModLength);

    //Extract all X and Y from ShareX.txt file
    //Notes: somehow Read Multiple Lines from File does not work, therefore rebuilt the Read
    uint64_t X[MINIMUM_SHARE], Y[MINIMUM_SHARE];
    for (int i = 0; i < MINIMUM_SHARE; i++) {
        char Filename[32];
        snprintf(Filename, sizeof Filename, "Share%d.txt", i + 1);

        FILE *f = fopen(Filename, "r");
        if (Filename == NULL)
	    {
            printf("Error opening file.\n");
            exit(0);
	    }
        char Line[LENGTH_OF_EACH_MESSAGE];

        //Extracting X value
        memset(Line, 0, sizeof Line);
        fgets(Line, sizeof Line, f);
        X[i] = str_to_uint64((unsigned char *)Line, strlen(Line));

        //Extracting Y value
        memset(Line, 0, sizeof Line);
        fgets(Line, sizeof Line, f);
        Y[i] = str_to_uint64((unsigned char *)Line, strlen(Line));

        fclose(f);
    }

    //Lagrange interpolation
    uint64_t Secret = 0;
    for (int i = 0; i < MINIMUM_SHARE; i++) {
        uint64_t Num = 1, Den = 1;
        for (int j = 0; j < MINIMUM_SHARE; j++) {
            if (j == i) continue;
            Num = (Num * (X[j] % p)) % p;
            Den = (Den * ((X[j] + p - X[i]) % p)) % p;
        }
        uint64_t Term = (Y[i] % p) * Num % p * modinv(Den, p) % p;
        Secret = (Secret + Term) % p;
    }

    unsigned char Output[32];
    uint64_to_str(Secret, Output, sizeof Output);
    Write_File("Recovered.txt", (char *)Output);

    free(Mod);
    return 0;
}