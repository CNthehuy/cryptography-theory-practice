/*************************************
 *      ECC BAF Sign and Update      *
 *************************************
 * Description:
 * 1. Reads elliptic curve parameters (curve name) from a parameter file.
 * 2. Loads a predefined list of messages from a message file.
 * 3. Reads the signer’s current private state (cur_j, a_cur, b_cur, x, x’)
 *    from a file.
 * 4. Generates an aggregate BAF signature over the list of messages:
 *      - Uses the current state (a_cur, b_cur, x, x’).
 *      - Advances the state with ECC_BAF_Update after each message.
 * 5. Saves the computed signature (s_0l, k_l) to signature.txt.
 * 6. Updates and saves the new private state to private_state.txt
 *    for future signing sessions.
 *
 * Compile:
 *   gcc -o ecc_baf_sign_and_update ecc_baf_sign_and_update.c -lcrypto
 *
 * Run:
 *   ./ecc_baf_sign_and_update ECCParams.txt Message.txt InitialPrivateState.txt
 *
 *Documentation:    OpenSSL Manual
 *
 * Created By:       *Lazar Lazarevic* 
 *************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>

#define MAX_L 16

// ECC curve context structure
typedef struct {
    EC_GROUP *group;
    EC_POINT *generator;
    BIGNUM *order;
    BN_CTX *bn_ctx;
} ECC_Context;

// Function prototypes
unsigned char* Read_File(char fileName[], int *fileLen);
void Show_BN(const char *label, const BIGNUM *bn);
int Read_ECC_Parameters_From_File(char *filename, ECC_Context *ecc_ctx);
unsigned char *PRNG(const unsigned char *seed, size_t seed_len, size_t output_len);
void BN_hash_to_Zn(const unsigned char *buf, size_t len, const BIGNUM *n, BIGNUM *out, BN_CTX *ctx);
void BN_H_bn_to_Zn(const BIGNUM *x, const BIGNUM *n, BIGNUM *out, BN_CTX *ctx);
void be64(uint64_t v, unsigned char out[8]);
void Read_Messages_From_File(const char *filename, char *msgs[], size_t lens[], int *count);
void Read_Private_State_From_File(const char *filename, int *cur_j,
                                 BIGNUM **a_cur, BIGNUM **b_cur,
                                 BIGNUM **x, BIGNUM **xp);
void Write_Private_State_To_File(const char *filename, int cur_j,
                                const BIGNUM *a_cur, const BIGNUM *b_cur,
                                const BIGNUM *x, const BIGNUM *xp);
void ECC_BAF_Update(int *cur_j, BIGNUM **a_cur, BIGNUM **b_cur,
                    const BIGNUM *n, BN_CTX *ctx);
void ECC_BAF_Sign(int l, const char *D[], const size_t Dlen[], int L,
                  int *cur_j, BIGNUM **a_cur, BIGNUM **b_cur,
                  const BIGNUM *x, const BIGNUM *xp,
                  const BIGNUM *n, BIGNUM *s_0l, BIGNUM **k_l, BN_CTX *ctx);

/*************************************************************
                        M A I N
**************************************************************/
int main(int argc, char **argv){
    if (argc < 4){
        fprintf(stderr, "Usage: %s ECCParams.txt Message.txt InitialPrivateState.txt\n", argv[0]);
        return 1;
    }

    OpenSSL_add_all_algorithms();

    // Initialize ECC context
    ECC_Context ecc_ctx = {0};
    if (!Read_ECC_Parameters_From_File(argv[1], &ecc_ctx)) {
        fprintf(stderr, "Failed to read ECC parameters\n");
        return 1;
    }

    printf("ECC Parameters loaded successfully\n");

    // messages
    char *D[MAX_L] = {0};
    size_t Dlen[MAX_L] = {0};
    int msg_count = 0;
    Read_Messages_From_File(argv[2], D, Dlen, &msg_count);

    int l = msg_count - 1;
    if (l >= MAX_L) l = MAX_L - 1;

    // Read private state from key generation
    int cur_j = 0;
    BIGNUM *a_cur = NULL;
    BIGNUM *b_cur = NULL;
    BIGNUM *x = NULL;
    BIGNUM *xp = NULL;

    Read_Private_State_From_File(argv[3], &cur_j, &a_cur, &b_cur, &x, &xp);
    printf("Private state loaded from file: cur_j=%d\n", cur_j);

    // Sign: uses current a_cur,b_cur and will call ECC_BAF_Update inside, advancing cur_j 
    BIGNUM *s_0l = BN_new(); 
    BN_zero(s_0l);
    BIGNUM *k_l = NULL;
    ECC_BAF_Sign(l, (const char **)D, Dlen, MAX_L, &cur_j, &a_cur, &b_cur, x, xp, ecc_ctx.order, s_0l, &k_l, ecc_ctx.bn_ctx);

    // save signature 
    FILE *sigfp = fopen("signature.txt", "w");
    char *sig_hex = BN_bn2hex(s_0l);
    char *kl_hex = BN_bn2hex(k_l);
    fprintf(sigfp, "s_0l: %s\nk_l: %s\n", sig_hex, kl_hex);
    OPENSSL_free(sig_hex);
    OPENSSL_free(kl_hex);
    fclose(sigfp);

    printf("Signature written to signature.txt\n");

    // Save updated private state for potential future use
    Write_Private_State_To_File("private_state.txt", cur_j, a_cur, b_cur, x, xp);
    printf("Updated private state saved to file\n");

    // cleanup
    if (a_cur) BN_free(a_cur);
    if (b_cur) BN_free(b_cur);
    if (x) BN_free(x);
    if (xp) BN_free(xp);
    BN_free(s_0l);
    BN_free(k_l);
    
    // cleanup ECC context
    if (ecc_ctx.group) EC_GROUP_free(ecc_ctx.group);
    if (ecc_ctx.generator) EC_POINT_free(ecc_ctx.generator);
    if (ecc_ctx.order) BN_free(ecc_ctx.order);
    if (ecc_ctx.bn_ctx) BN_CTX_free(ecc_ctx.bn_ctx);
    
    for (int i=0;i<msg_count;i++) free(D[i]);

    EVP_cleanup();
    return 0;
}

/*============================
        Read from File
==============================*/

unsigned char* Read_File(char fileName[], int *fileLen)
{
    FILE *pFile = fopen(fileName, "r");
    if (pFile == NULL) { perror("open file"); return NULL; }
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1;
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size);
    if (!fgets((char*)output, temp_size, pFile)) { fclose(pFile); free(output); return NULL; }
    fclose(pFile);
    *fileLen = temp_size-1;
    return output;
}

/*============================
    Show BIGNUM
==============================*/
void Show_BN(const char *label, const BIGNUM *bn){
    char *hex = BN_bn2hex(bn);
    if (!hex) { printf("%s: (error)\n", label); return; }
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
}

/*============================
    Read ECC Parameters From File
==============================*/
int Read_ECC_Parameters_From_File(char *filename, ECC_Context *ecc_ctx)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL) { 
        fprintf(stderr, "Error opening ECC parameter file: %s\n", filename); 
        return 0; 
    }
    
    char line[1024];
    char curve_name[256];
    
    // Read curve name
    if (fgets(line, sizeof(line), file) != NULL){
        if (sscanf(line, "curve: %s", curve_name) == 1) {
            printf("Using curve: %s\n", curve_name);
        } else { 
            fprintf(stderr,"Failed to parse curve name\n"); 
            fclose(file);
            return 0; 
        }
    } else { 
        fprintf(stderr,"Failed to read curve name\n"); 
        fclose(file);
        return 0; 
    }
    fclose(file);

    // Initialize BN context
    ecc_ctx->bn_ctx = BN_CTX_new();
    if (!ecc_ctx->bn_ctx) {
        fprintf(stderr, "Failed to create BN_CTX\n");
        return 0;
    }

    // Create curve based on name
    int nid;
    if (strcmp(curve_name, "secp256r1") == 0 || strcmp(curve_name, "prime256v1") == 0) {
        nid = NID_X9_62_prime256v1;
    } else if (strcmp(curve_name, "secp256k1") == 0) {
        nid = NID_secp256k1;
    } else if (strcmp(curve_name, "secp384r1") == 0) {
        nid = NID_secp384r1;
    } else {
        fprintf(stderr, "Unsupported curve: %s\n", curve_name);
        BN_CTX_free(ecc_ctx->bn_ctx);
        return 0;
    }

    ecc_ctx->group = EC_GROUP_new_by_curve_name(nid);
    if (!ecc_ctx->group) {
        fprintf(stderr, "Failed to create EC_GROUP\n");
        BN_CTX_free(ecc_ctx->bn_ctx);
        return 0;
    }

    // Get generator point
    ecc_ctx->generator = EC_POINT_new(ecc_ctx->group);
    const EC_POINT *gen_point = EC_GROUP_get0_generator(ecc_ctx->group);
    if (!ecc_ctx->generator || !gen_point) {
        fprintf(stderr, "Failed to get generator point\n");
        EC_GROUP_free(ecc_ctx->group);
        BN_CTX_free(ecc_ctx->bn_ctx);
        return 0;
    }
    if (!EC_POINT_copy(ecc_ctx->generator, gen_point)) {
        fprintf(stderr, "Failed to copy generator point\n");
        EC_POINT_free(ecc_ctx->generator);
        EC_GROUP_free(ecc_ctx->group);
        BN_CTX_free(ecc_ctx->bn_ctx);
        return 0;
    }

    // Get order
    ecc_ctx->order = BN_new();
    if (!ecc_ctx->order || !EC_GROUP_get_order(ecc_ctx->group, ecc_ctx->order, ecc_ctx->bn_ctx)) {
        fprintf(stderr, "Failed to get curve order\n");
        BN_free(ecc_ctx->order);
        EC_POINT_free(ecc_ctx->generator);
        EC_GROUP_free(ecc_ctx->group);
        BN_CTX_free(ecc_ctx->bn_ctx);
        return 0;
    }

    return 1;
}

/*============================
        PRNG Function 
==============================*/
unsigned char* PRNG(const unsigned char *seed, size_t seed_len, size_t output_len)
{
    // User-provided seed (must be 32 bytes for ChaCha20)
    if (seed_len != 32) {
        printf("Seed length must be 32 bytes.\n");
        return NULL;
    }

    // Fixed and zeroed iv (16 bytes (4 counter, 12 nonce)) for deterministic output
    unsigned char iv[16] = {0};

    // Output buffer
    unsigned char* output = malloc(output_len + 1); // +1 for possible null terminator
    unsigned char plaintext[output_len];
    memset(plaintext, 0, sizeof(plaintext));  // Encrypting zeros

    // Initialize ChaCha20 context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Failed to create cipher context.\n");
        return NULL;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "Failed to initialize cipher.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Set seed and nonce
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, seed, iv) != 1) {
        fprintf(stderr, "Failed to set key and nonce.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    // Encrypt (in the context of chacha20, simply XORs plaintext with keystream, and since plaintext is zeroes, result is just keystream)
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, output, &outlen, plaintext, sizeof(plaintext)) != 1) {
        fprintf(stderr, "Encryption failed.\n");
        EVP_CIPHER_CTX_free(ctx);
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);

    return output;
}

/*============================
        BN hash to Z_n 
==============================*/
void BN_hash_to_Zn(const unsigned char *buf, size_t len, const BIGNUM *n, BIGNUM *out, BN_CTX *ctx){
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256(buf, len, md);
    BIGNUM *tmp = BN_bin2bn(md, SHA256_DIGEST_LENGTH, NULL);
    BN_mod(out, tmp, n, ctx);
    if (BN_is_zero(out)) BN_one(out);
    BN_clear_free(tmp);
}

/*============================
        BN H bn to Z_n 
==============================*/
void BN_H_bn_to_Zn(const BIGNUM *x, const BIGNUM *n, BIGNUM *out, BN_CTX *ctx){
    int blen = BN_num_bytes(x);
    unsigned char *buf = malloc((size_t)blen);
    BN_bn2bin(x, buf);
    BN_hash_to_Zn(buf, (size_t)blen, n, out, ctx);
    free(buf);
}

/*============================
        uint64_t to be64 
==============================*/
void be64(uint64_t v, unsigned char out[8]){ 
    for (int i=7;i>=0;--i){ 
        out[i] = (unsigned char)(v & 0xff); 
        v >>= 8; 
    } 
}

/*============================
    Read Messages from File
==============================*/
void Read_Messages_From_File(const char *filename, char *msgs[], size_t lens[], int *count) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("Message file open failed"); exit(1); }
    char buffer[4096];
    if (!fgets(buffer, sizeof(buffer), fp)) { perror("Message file read failed"); exit(1); }
    fclose(fp);

    char *token = strtok(buffer, ",");
    int idx = 0;
    while (token && idx < MAX_L) {
        while (isspace((unsigned char)*token)) token++;
        size_t len = strlen(token);
        while (len > 0 && isspace((unsigned char)token[len-1])) token[--len] = '\0';
        msgs[idx] = strdup(token);
        lens[idx] = strlen(msgs[idx]);
        idx++;
        token = strtok(NULL, ",");
    }
    *count = idx;
}

/*============================
    Read Private State from File
==============================*/
void Read_Private_State_From_File(const char *filename, int *cur_j,
                                 BIGNUM **a_cur, BIGNUM **b_cur,
                                 BIGNUM **x, BIGNUM **xp) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Could not open %s for reading\n", filename);
        exit(1);
    }
    
    char line[1024];
    *a_cur = BN_new();
    *b_cur = BN_new();
    *x = BN_new();
    *xp = BN_new();
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "cur_j:", 6) == 0) {
            sscanf(line, "cur_j: %d", cur_j);
        } else if (strncmp(line, "a_cur:", 6) == 0) {
            char *hex_start = line + 6;
            while (isspace((unsigned char)*hex_start)) hex_start++;
            char *hex_end = hex_start + strlen(hex_start) - 1;
            while (hex_end > hex_start && isspace((unsigned char)*hex_end)) *hex_end-- = '\0';
            
            if (!BN_hex2bn(a_cur, hex_start)) {
                fprintf(stderr, "Error: Failed to parse a_cur\n");
                exit(1);
            }
        } else if (strncmp(line, "b_cur:", 6) == 0) {
            char *hex_start = line + 6;
            while (isspace((unsigned char)*hex_start)) hex_start++;
            char *hex_end = hex_start + strlen(hex_start) - 1;
            while (hex_end > hex_start && isspace((unsigned char)*hex_end)) *hex_end-- = '\0';
            
            if (!BN_hex2bn(b_cur, hex_start)) {
                fprintf(stderr, "Error: Failed to parse b_cur\n");
                exit(1);
            }
        } else if (strncmp(line, "x:", 2) == 0) {
            char *hex_start = line + 2;
            while (isspace((unsigned char)*hex_start)) hex_start++;
            char *hex_end = hex_start + strlen(hex_start) - 1;
            while (hex_end > hex_start && isspace((unsigned char)*hex_end)) *hex_end-- = '\0';
            
            if (!BN_hex2bn(x, hex_start)) {
                fprintf(stderr, "Error: Failed to parse x\n");
                exit(1);
            }
        } else if (strncmp(line, "xp:", 3) == 0) {
            char *hex_start = line + 3;
            while (isspace((unsigned char)*hex_start)) hex_start++;
            char *hex_end = hex_start + strlen(hex_start) - 1;
            while (hex_end > hex_start && isspace((unsigned char)*hex_end)) *hex_end-- = '\0';
            
            if (!BN_hex2bn(xp, hex_start)) {
                fprintf(stderr, "Error: Failed to parse xp\n");
                exit(1);
            }
        }
    }
    fclose(fp);
}

/*============================
    Write Private State to File
==============================*/
void Write_Private_State_To_File(const char *filename, int cur_j,
                                const BIGNUM *a_cur, const BIGNUM *b_cur,
                                const BIGNUM *x, const BIGNUM *xp) {
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        fprintf(stderr, "Error: Could not open %s for writing\n", filename);
        exit(1);
    }
    
    char *a_hex = BN_bn2hex(a_cur);
    char *b_hex = BN_bn2hex(b_cur);
    char *x_hex = BN_bn2hex(x);
    char *xp_hex = BN_bn2hex(xp);
    
    fprintf(fp, "cur_j: %d\n", cur_j);
    fprintf(fp, "a_cur: %s\n", a_hex);
    fprintf(fp, "b_cur: %s\n", b_hex);
    fprintf(fp, "x: %s\n", x_hex);
    fprintf(fp, "xp: %s\n", xp_hex);
    
    OPENSSL_free(a_hex);
    OPENSSL_free(b_hex);
    OPENSSL_free(x_hex);
    OPENSSL_free(xp_hex);
    fclose(fp);
}

/*============================
        ECC BAF Update
==============================*/
void ECC_BAF_Update(int *cur_j, BIGNUM **a_cur, BIGNUM **b_cur,
                    const BIGNUM *n, BN_CTX *ctx)
{
    BIGNUM *a_next = BN_new();
    BIGNUM *b_next = BN_new();

    // a_next = H(a_cur) mod n, b_next = H(b_cur) mod n
    BN_H_bn_to_Zn(*a_cur, n, a_next, ctx);
    BN_H_bn_to_Zn(*b_cur, n, b_next, ctx);

    // secure erase old values
    BN_clear(*a_cur);
    BN_clear(*b_cur);
    BN_copy(*a_cur, a_next);
    BN_copy(*b_cur, b_next);

    BN_clear_free(a_next);
    BN_clear_free(b_next);

    (*cur_j)++;
}

/*============================
        ECC BAF Sign
==============================*/
void ECC_BAF_Sign(int l, const char *D[], const size_t Dlen[], int L,
                  int *cur_j, BIGNUM **a_cur, BIGNUM **b_cur,
                  const BIGNUM *x, const BIGNUM *xp,
                  const BIGNUM *n, BIGNUM *s_0l, BIGNUM **k_l, BN_CTX *ctx)
{
    (void)L;
    BIGNUM *r_m  = BN_new();
    BIGNUM *h_m  = BN_new();
    BIGNUM *term = BN_new();
    BN_zero(s_0l);

    int xlen = BN_num_bytes(x);

    for (int m = *cur_j; m <= l; m++) {
        unsigned char *buf;

        // r_m = H(x || m) mod n
        buf = malloc((size_t)xlen + 8);
        BN_bn2bin(x, buf);
        be64((uint64_t)m, buf + xlen);
        BN_hash_to_Zn(buf, (size_t)xlen + 8, n, r_m, ctx);
        free(buf);

        // h_m = H(D_m || r_m || m) mod n
        int rlen = BN_num_bytes(r_m);
        buf = malloc(Dlen[m] + (size_t)rlen + 8);
        memcpy(buf, D[m], Dlen[m]);
        BN_bn2bin(r_m, buf + Dlen[m]);
        be64((uint64_t)m, buf + Dlen[m] + rlen);
        BN_hash_to_Zn(buf, Dlen[m] + (size_t)rlen + 8, n, h_m, ctx);
        free(buf);

        // term = (a_cur * h_m + b_cur) mod n ; sigma += term
        BN_mod_mul(term, *a_cur, h_m, n, ctx);
        BN_mod_add(term, term, *b_cur, n, ctx);
        BN_mod_add(s_0l, s_0l, term, n, ctx);

        // advance state
        ECC_BAF_Update(cur_j, a_cur, b_cur, n, ctx);
    }

    // k_l = H(x' || l) mod n
    int xplen = BN_num_bytes(xp);
    unsigned char *kbuf = malloc((size_t)xplen + 8);
    BN_bn2bin(xp, kbuf);
    be64((uint64_t)l, kbuf + xplen);
    *k_l = BN_new();
    BN_hash_to_Zn(kbuf, (size_t)xplen + 8, n, *k_l, ctx);
    free(kbuf);

    BN_clear_free(r_m);
    BN_clear_free(h_m);
    BN_clear_free(term);
}