/*************************************
 *          ECC BAF Verify            *
 *************************************
 * Description:
 * 1. Reads elliptic curve parameters (curve name) from a parameter file.
 * 2. Loads a list of messages from a message file (comma-separated).
 * 3. Loads the combined public verification vector (A[], B[], u[], u’[]) 
 *    from a file.
 * 4. Reads the signature (s_0l, k_l) from signature.txt.
 * 5. Reconstructs the verification values:
 *      - Recovers the chain of k_j values backwards from k_l and u’[].
 *      - Computes r_j = u_j – k_j (mod n).
 *      - For each message, computes h_j = H(D_j || r_j || j).
 *      - Aggregates elliptic curve points sum(h_j * A_j + B_j).
 * 6. Verifies correctness by checking:
 *        s_0l * G ?= Σ (h_j * A_j + B_j).
 * 7. Writes the result (“VALID” or “INVALID”) to verify_result.txt.
 *
 * Compile:
 *   gcc -o ecc_baf_verify ecc_baf_verify.c -lcrypto
 *
 * Run:
 *   ./ecc_baf_verify ECCParams.txt Message.txt PublicVector.txt
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
void Show_Point(const char *label, const EC_POINT *point, const EC_GROUP *group, BN_CTX *ctx);
void Show_BN(const char *label, const BIGNUM *bn);
int Read_ECC_Parameters_From_File(char *filename, ECC_Context *ecc_ctx);
void BN_hash_to_Zn(const unsigned char *buf, size_t len, const BIGNUM *n, BIGNUM *out, BN_CTX *ctx);
void BN_H_bn_to_Zn(const BIGNUM *x, const BIGNUM *n, BIGNUM *out, BN_CTX *ctx);
void be64(uint64_t v, unsigned char out[8]);
void Read_Messages_From_File(const char *filename, char *msgs[], size_t lens[], int *count);
void Read_Combined_Public_Vector_From_File(const char *filename,
                                          EC_POINT *A[], EC_POINT *B[],
                                          BIGNUM *u[], BIGNUM *up[],
                                          int L, const EC_GROUP *group);
void Read_Signature_From_File(const char *filename, BIGNUM **s_0l, BIGNUM **k_l);
int ECC_BAF_Verify(int start_j, int l, const char *D[], const size_t Dlen[], int L,
                   const EC_POINT *A[], const EC_POINT *B[],
                   const BIGNUM *u[], const BIGNUM *up[],
                   const ECC_Context *ecc_ctx,
                   const BIGNUM *s_0l, const BIGNUM *k_l);

/*************************************************************
                        M A I N
**************************************************************/
int main(int argc, char **argv){
    if (argc < 4){
        fprintf(stderr, "Usage: %s ECCParams.txt Message.txt PublicVector.txt\n", argv[0]);
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

    int L = MAX_L;

    // public arrays (to be loaded from files)
    EC_POINT *A[MAX_L]  = {0};
    EC_POINT *B[MAX_L]  = {0};
    BIGNUM *u[MAX_L]  = {0};
    BIGNUM *up[MAX_L] = {0};

    // Read combined public vector from file
    Read_Combined_Public_Vector_From_File(argv[3], A, B, u, up, L, ecc_ctx.group);

    // messages
    char *D[MAX_L] = {0};
    size_t Dlen[MAX_L] = {0};
    int msg_count = 0;
    Read_Messages_From_File(argv[2], D, Dlen, &msg_count);

    int l = msg_count - 1;
    if (l >= L) l = L - 1;

    // Read signature from file
    BIGNUM *s_0l = NULL;
    BIGNUM *k_l = NULL;
    Read_Signature_From_File("signature.txt", &s_0l, &k_l);

    // verify using public arrays and tokens
    int verify = ECC_BAF_Verify(0, l, (const char **)D, Dlen, L, (const EC_POINT **)A, (const EC_POINT **)B,
                                (const BIGNUM **)u, (const BIGNUM **)up, &ecc_ctx, s_0l, k_l);

    FILE *verfp = fopen("verify_result.txt", "w");
    fprintf(verfp, "%s\n", verify ? "VALID" : "INVALID");
    fclose(verfp);

    printf("Verification result: %s\n", verify ? "VALID" : "INVALID");

    // cleanup
    for (int j=0;j<L;j++){
        if (A[j]) EC_POINT_free(A[j]);
        if (B[j]) EC_POINT_free(B[j]);
        if (u[j]) BN_free(u[j]);
        if (up[j]) BN_free(up[j]);
    }
    BN_free(s_0l); 
    BN_free(k_l);
    
    // cleanup ECC context
    if (ecc_ctx.group) EC_GROUP_free(ecc_ctx.group);
    if (ecc_ctx.generator) EC_POINT_free(ecc_ctx.generator);
    if (ecc_ctx.order) BN_free(ecc_ctx.order);
    if (ecc_ctx.bn_ctx) BN_CTX_free(ecc_ctx.bn_ctx);
    
    for (int i=0;i<msg_count;i++) free(D[i]);

    EVP_cleanup();
    return verify ? 0 : 1;
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
    Show EC_POINT
==============================*/
void Show_Point(const char *label, const EC_POINT *point, const EC_GROUP *group, BN_CTX *ctx){
    char *hex = EC_POINT_point2hex(group, point, POINT_CONVERSION_UNCOMPRESSED, ctx);
    if (!hex) { printf("%s: (error)\n", label); return; }
    printf("%s: %s\n", label, hex);
    OPENSSL_free(hex);
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
  Read Combined Public Vector from File
==============================*/
void Read_Combined_Public_Vector_From_File(const char *filename,
                                          EC_POINT *A[], EC_POINT *B[],
                                          BIGNUM *u[], BIGNUM *up[],
                                          int L, const EC_GROUP *group) {
    FILE *fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Could not open %s for reading\n", filename);
        exit(1);
    }
    
    char line[4096];
    int idx = 0;
    
    while (fgets(line, sizeof(line), fp) && idx < L) {
        // Parse: A[i]=...,B[i]=...,u[i]=...,up[i]=...
        char *A_start = strstr(line, "A[");
        char *B_start = strstr(line, "B[");
        char *u_start = strstr(line, "u[");
        char *up_start = strstr(line, "up[");
        
        if (!A_start || !B_start || !u_start || !up_start) {
            fprintf(stderr, "Error: Invalid format in %s at line %d\n", filename, idx + 1);
            exit(1);
        }
        
        // Extract A[i] value
        char *A_eq = strchr(A_start, '=');
        char *A_comma = strchr(A_eq, ',');
        if (A_eq && A_comma) {
            *A_comma = '\0';
            char *A_hex = A_eq + 1;
            if (strcmp(A_hex, "NULL") == 0) {
                A[idx] = NULL;
            } else {
                A[idx] = EC_POINT_new(group);
                if (!EC_POINT_hex2point(group, A_hex, A[idx], NULL)) {
                    EC_POINT_free(A[idx]);
                    A[idx] = NULL;
                }
            }
            *A_comma = ','; // restore
        }
        
        // Extract B[i] value
        char *B_eq = strchr(B_start, '=');
        char *B_comma = strchr(B_eq, ',');
        if (B_eq && B_comma) {
            *B_comma = '\0';
            char *B_hex = B_eq + 1;
            if (strcmp(B_hex, "NULL") == 0) {
                B[idx] = NULL;
            } else {
                B[idx] = EC_POINT_new(group);
                if (!EC_POINT_hex2point(group, B_hex, B[idx], NULL)) {
                    EC_POINT_free(B[idx]);
                    B[idx] = NULL;
                }
            }
            *B_comma = ','; // restore
        }
        
        // Extract u[i] value
        char *u_eq = strchr(u_start, '=');
        char *u_comma = strchr(u_eq, ',');
        if (u_eq && u_comma) {
            *u_comma = '\0';
            char *u_hex = u_eq + 1;
            if (strcmp(u_hex, "NULL") == 0) {
                u[idx] = NULL;
            } else {
                u[idx] = BN_new();
                if (!BN_hex2bn(&u[idx], u_hex)) {
                    BN_free(u[idx]);
                    u[idx] = NULL;
                }
            }
            *u_comma = ','; // restore
        }
        
        // Extract up[i] value
        char *up_eq = strchr(up_start, '=');
        char *up_end = up_eq + strlen(up_eq);
        // Remove newline
        while (up_end > up_eq && (*up_end == '\n' || *up_end == '\r' || *up_end == '\0')) up_end--;
        *(up_end + 1) = '\0';
        
        if (up_eq) {
            char *up_hex = up_eq + 1;
            if (strcmp(up_hex, "NULL") == 0 || idx == 0) {
                up[idx] = NULL;
            } else {
                up[idx] = BN_new();
                if (!BN_hex2bn(&up[idx], up_hex)) {
                    BN_free(up[idx]);
                    up[idx] = NULL;
                }
            }
        }
        
        idx++;
    }
    fclose(fp);
    
    // Initialize remaining elements to NULL
    for (int i = idx; i < L; i++) {
        A[i] = NULL;
        B[i] = NULL;
        u[i] = NULL;
        up[i] = NULL;
    }
}

/*============================
    Read Signature from File 
==============================*/
void Read_Signature_From_File(const char *filename, BIGNUM **s_0l, BIGNUM **k_l) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { 
        fprintf(stderr, "Error: Could not open signature file %s\n", filename);
        exit(1);
    }
    
    char line[1024];
    *s_0l = NULL;
    *k_l = NULL;
    
    while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "s_0l:", 5) == 0) {
            char *hex_start = line + 5;
            while (isspace((unsigned char)*hex_start)) hex_start++;
            char *hex_end = hex_start + strlen(hex_start) - 1;
            while (hex_end > hex_start && isspace((unsigned char)*hex_end)) *hex_end-- = '\0';
            
            *s_0l = BN_new();
            if (!BN_hex2bn(s_0l, hex_start)) {
                BN_free(*s_0l);
                *s_0l = NULL;
            }
        } else if (strncmp(line, "k_l:", 4) == 0) {
            char *hex_start = line + 4;
            while (isspace((unsigned char)*hex_start)) hex_start++;
            char *hex_end = hex_start + strlen(hex_start) - 1;
            while (hex_end > hex_start && isspace((unsigned char)*hex_end)) *hex_end-- = '\0';
            
            *k_l = BN_new();
            if (!BN_hex2bn(k_l, hex_start)) {
                BN_free(*k_l);
                *k_l = NULL;
            }
        }
    }
    fclose(fp);
    
    if (!*s_0l || !*k_l) {
        fprintf(stderr, "Error: Failed to read signature components\n");
        exit(1);
    }
}

/*============================
        ECC BAF Verify
==============================*/
int ECC_BAF_Verify(int start_j, int l, const char *D[], const size_t Dlen[], int L,
                   const EC_POINT *A[], const EC_POINT *B[],
                   const BIGNUM *u[], const BIGNUM *up[],
                   const ECC_Context *ecc_ctx,
                   const BIGNUM *s_0l, const BIGNUM *k_l)
{

/*============================================
        YOUR CODE HERE
    Reconstruct k[l]..k[0] and r[l]..r[0] here.
=============================================*/
    BIGNUM *krec[MAX_L] = {0};
    BIGNUM *rrec[MAX_L] = {0};
    const BIGNUM *n = ecc_ctx->order;
    BN_CTX *ctx = ecc_ctx->bn_ctx;

    if(start_j != 0 || l < 0 || l >= L || l >= MAX_L || !s_0l || !k_l || !n || !ctx){
        return 0;
    }

    for(int j = 0; j <= l; j++){
        krec[j] = BN_new();
        rrec[j] = BN_new();
        if(!krec[j] || !rrec[j]){
            return 0;
        }
    }

    if(!BN_copy(krec[l], k_l)){
        return 0;
    }

    BIGNUM *hashedK = BN_new();
    if(!hashedK){
        return 0;
    }
    
    for(int j = l; j >= 1; j--){
        if(!up[j]){
            BN_free(hashedK);
            return 0;
        }
        BN_H_bn_to_Zn(krec[j], n, hashedK, ctx);
        if(!BN_mod_sub(krec[j - 1], up[j], hashedK, n, ctx)){
            BN_free(hashedK);
            return 0;
        }
    }
    BN_free(hashedK);

    for(int j = 0; j <= l; j++){
        if(!u[j] || !BN_mod_sub(rrec[j], u[j], krec[j], n, ctx)){
            return 0;
        }
    }
    
  //======Save reconstructed_k.txt and reconstructed_r.txt======//
  //===================DO NOT ALTER THIS CODE===================//
    FILE *k_file = fopen("reconstructed_k.txt", "w");
    for (int j = 0; j <= l; j++) {
        char *hex = BN_bn2hex(krec[j]);
        fprintf(k_file, "K[%d]: %s\n", j, hex);
        OPENSSL_free(hex);
    }
    fclose(k_file);

    FILE *r_file = fopen("reconstructed_r.txt", "w");
    for (int j = 0; j <= l; j++) {
        char *hex = BN_bn2hex(rrec[j]);
        fprintf(r_file, "R[%d]: %s\n", j, hex);
        OPENSSL_free(hex);
    }
    fclose(r_file);
  //============================================================//

/*============================================
        YOUR CODE HERE
    Compute LHS and RHS and compare them.
    Return 1 if they are equal, 0 otherwise.
=============================================*/
    EC_POINT *lhs = EC_POINT_new(ecc_ctx->group);
    EC_POINT *rhs = EC_POINT_new(ecc_ctx->group);
    EC_POINT *term = EC_POINT_new(ecc_ctx->group);
    BIGNUM *h = BN_new();
    int valid = 0;

    if(lhs && rhs && term && h && EC_POINT_mul(ecc_ctx->group, lhs, s_0l, NULL, NULL, ctx) && EC_POINT_set_to_infinity(ecc_ctx->group, rhs)){
        valid = 1;
        for(int j = 0; j <= l; j++){
            if(!A[j] || !B[j] || !D[j]){
                valid = 0;
                break;
            }
            int rlen = BN_num_bytes(rrec[j]);
            size_t len = Dlen[j] + (size_t)rlen + 8;
            
            unsigned char *buf = malloc(len);
            if(!buf){
                valid = 0;
                break;
            }
            memcpy(buf, D[j], Dlen[j]);
            BN_bn2bin(rrec[j], buf + Dlen[j]);
            be64((uint64_t)j, buf + Dlen[j] + rlen);
            BN_hash_to_Zn(buf, len, n, h, ctx);
            free(buf);

            if(!EC_POINT_mul(ecc_ctx->group, term, NULL, A[j], h, ctx) || !EC_POINT_add(ecc_ctx->group, term, term, B[j], ctx) || !EC_POINT_add(ecc_ctx->group, rhs, rhs, term, ctx)){
                valid = 0;
                break;
            }
        }
        if(valid){
            valid = (EC_POINT_cmp(ecc_ctx->group, lhs, rhs, ctx) == 0);
        }
    }
    EC_POINT_free(lhs);
    EC_POINT_free(rhs);
    EC_POINT_free(term);
    BN_free(h);
    for(int j = 0; j <= l; j++){
        BN_free(krec[j]);
        BN_free(rrec[j]);
    }
    return valid;
}