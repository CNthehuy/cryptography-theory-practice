#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>

int64_t gcd(int64_t a, int64_t b);

int main(int argc, char *argv[]){
    int64_t a = strtoll(argv[1], NULL, 10);
    int64_t b = strtoll(argv[2], NULL, 10);

    int64_t value = gcd(a, b);
    printf("%ld\n", value);
    //printf("\n");

    return 0;
}

int64_t gcd(int64_t a, int64_t b){
    while(a != 0){
        int64_t tmp = b % a;
        b = a;
        a = tmp;
    }
    return b;
}