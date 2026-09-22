#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <gmp.h>
#include <time.h>


//given functions
typedef __int128 int128_t;
#define SHIFT_LEFT(x, n)   ((x) << (n))
#define SHIFT_RIGHT(x, n)  ((x) >> (n))
#define UPPER_64(x) ((unsigned long)((x) >> 64))
#define LOWER_64(x) ((unsigned long)(x))
int128_t str_to_int128(const unsigned char *str, int str_len);
void int128_to_str(int128_t value, unsigned char *output, int output_len);
unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[]);

int128_t snm128(int128_t base, int128_t expo, int128_t mod);
int128_t gcd128(int128_t a, int128_t b);
void eea128(int128_t *gcd, int128_t *x, int128_t *y, int128_t a, int128_t b);

typedef struct{
    int128_t x;
    int128_t a;
    int128_t b;
} RhoState;

int128_t posMod(int128_t value, int128_t mod);
int128_t randomMod(int128_t mod);
RhoState randomState(int128_t alpha, int128_t y, int128_t p, int128_t order);
void rho_step(RhoState *state, int128_t alpha, int128_t y, int128_t p, int128_t order);
int fixCollision(int128_t *answer, RhoState tortoise, RhoState hare, int128_t alpha, int128_t y, int128_t p, int128_t order);
int128_t pr(int128_t alpha, int128_t y, int128_t p);
int128_t mul_mod(int128_t a, int128_t b, int128_t p);

int main(int argc, char *argv[]){
    int alphaLen = 0;
    int yLen = 0;
    int pLen = 0;

    unsigned char *alphaString = Read_File(argv[1], &alphaLen);
    unsigned char *yString = Read_File(argv[2], &yLen);
    unsigned char *pString = Read_File(argv[3], &pLen);

    int128_t alpha = str_to_int128(alphaString, alphaLen);
    int128_t y = str_to_int128(yString, yLen);
    int128_t p = str_to_int128(pString, pLen);

    free(alphaString);
    free(yString);
    free(pString);

    srand((unsigned int)time(NULL));

    int128_t expo = pr(alpha, y, p);

    unsigned char output[50];

    int128_to_str(expo, output, sizeof(output));

    Write_File("Result.txt", (char *)output);

    return 0;
}

int128_t posMod(int128_t value, int128_t mod){
    value %= mod;
    if(value < 0){
        value += mod;
    }
    return value;
}

int128_t randomMod(int128_t mod){
    int128_t value = 0;
    for(int i = 0; i < 5; i++){
        value = SHIFT_LEFT(value, 15);
        value += (rand() & 0x7fff);
    }
    return value % mod;
}

RhoState randomState(int128_t alpha, int128_t y, int128_t p, int128_t order){
    RhoState state;
    state.a = randomMod(order);
    state.b = randomMod(order);

    int128_t left = snm128(alpha, state.a, p);
    int128_t right = snm128(y, state.b, p);
    state.x = mul_mod(left, right, p);
    return state;
}

void rho_step(RhoState *state, int128_t alpha, int128_t y, int128_t p, int128_t order){
    int partition = state->x % 3;
    if(partition == 0){
        state->x = mul_mod(state->x, y, p);
        state->b = posMod(state->b + 1, order);
    }else if(partition == 1){
        state->x = mul_mod(state->x, y, p);
        state->b = posMod(state->b + 1, order);
    }else{
        state->x = mul_mod(state->x, state->x, p);
        state->a = posMod(2 * state->a, order);
        state->b = posMod(2 * state->b, order);
    }
}

int fixCollision(int128_t *answer, RhoState tortoise, RhoState hare, int128_t alpha, int128_t y, int128_t p, int128_t order){
    int128_t coeffi = posMod(hare.b - tortoise.b, order);
    int128_t rhs = posMod(tortoise.a - hare.a, order);

    if(coeffi == 0){
        return 0;
    }
    int128_t g;
    int128_t xCoeffi;
    int128_t yCoeffi;

    eea128(&g, &xCoeffi, &yCoeffi, coeffi, order);

    if((rhs % g) != 0){
        return 0;
    }

    int128_t newCoeffi = coeffi / g;
    int128_t newRHS = rhs / g;
    int128_t newOrder = order / g;

    int128_t newGCD;
    int128_t inverse;
    int128_t tmp;

    eea128(&newGCD, &inverse, &tmp, newCoeffi, newOrder);

    inverse = posMod(inverse, newOrder);

    int128_t baseSol = mul_mod(newRHS, inverse, newOrder);

    for(int128_t k = 0; k < g; k++){
        int128_t cand = baseSol + k * newOrder;

        if(snm128(alpha, cand, p) == y){
            *answer = cand;
            return 1;
        }
    }
    return 0;
}

int128_t pr(int128_t alpha, int128_t y, int128_t p){
    int128_t order = p - 1;
    
    while(1){
        RhoState tortoise = randomState(alpha, y, p, order);
        RhoState hare = tortoise;

        do{
            rho_step(&tortoise, alpha, y, p, order);
            rho_step(&hare, alpha, y, p, order);
            rho_step(&hare, alpha, y, p, order);
        }while(tortoise.x != hare.x);

        int128_t answer;
        if(fixCollision(&answer, tortoise, hare, alpha, y, p, order)){
            return answer;
        }
    }
}

//rewritten to 128
int128_t gcd128(int128_t a, int128_t b){
    while(a != 0){
        int128_t tmp = b % a;
        b = a;
        a = tmp;
    }
    return b;
}

//rewritten to 128
void eea128(int128_t *gcd, int128_t *x, int128_t *y, int128_t a, int128_t b){
    int128_t oldR = a;
    int128_t r = b;
    int128_t oldS = 1;
    int128_t s = 0;
    int128_t oldT = 0;
    int128_t t = 1;

    while(r != 0){
        int128_t q = oldR / r;
        int128_t tmp = oldR - q * r;
        oldR = r;
        r = tmp;

        tmp = oldS - q * s;
        oldS = s;
        s = tmp;

        tmp = oldT - q * t;
        oldT = t;
        t = tmp;
    }
    *gcd = oldR;
    *x = oldS;
    *y = oldT;
}

//rewritten to 128
int128_t mul_mod(int128_t a, int128_t b, int128_t p){
    return (a * b) % p;
}

//rewritten to 128
int128_t snm128(int128_t base, int128_t expo, int128_t mod){
    int128_t result = 1;
    base %= mod;

    while(expo > 0){
        if(expo & 1){
            result = mul_mod(result, base, mod);
        }
        base = mul_mod(base, base, mod);
        expo = SHIFT_RIGHT(expo, 1);
    }
    return result;
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

//given function
int128_t str_to_int128(const unsigned char *str, int str_len) {
    int128_t result = 0;
    int negative = 0;
    if (*str == '-') {
        negative = 1;
        str++;
    }
    for (int i=0; i < str_len && *str >= '0' && *str <= '9'; i++) {
        result = result * 10 + (*str - '0');
        str++;
    }
    return negative ? -result : result;
}

//given function
void int128_to_str(int128_t value, unsigned char *output, int output_len) {
    int negative = value < 0;
    if (negative) 
        value = -value;

    // Not going to need more than 40 digits, make it 50 just to be safe
    char temp[50];
    int i = 0;

    // In reverse order, reversed at the end
    do {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    } while (value > 0 && i < (int)sizeof(temp) - 1);

    if (negative) 
        temp[i++] = '-';

    if (i >= output_len) {
        output[0] = '\0';  // Not enough space
        return;
    }

    // Reverse the string into the output
    for (int j = 0; j < i; j++) {
        output[j] = temp[i - j - 1];
    }
    // Null-terminate
    output[i] = '\0';
}