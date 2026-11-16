#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// Helper functions

char* Read_File(const char *filename, long *fileLen) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file %s\n", filename);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    *fileLen = ftell(file);
    fseek(file, 0, SEEK_SET);
    char *content = malloc(*fileLen + 1);
    if (!content) {
        fclose(file);
        return NULL;
    }
    size_t n = fread(content, 1, *fileLen, file);
    content[n] = '\0';
    *fileLen = (long)n;
    fclose(file);
    return content;
}

int Convert_from_Hex(uint8_t *output, const char *hex_input, size_t max_len) {
    size_t hex_len = strlen(hex_input);
    int bytes = 0;
    for (size_t i = 0; i + 1 < hex_len; i += 2) {
        if (!isxdigit((unsigned char)hex_input[i]) || !isxdigit((unsigned char)hex_input[i+1])) {
            continue;
        }
        if ((size_t)bytes >= max_len) break;
        sscanf(&hex_input[i], "%2hhx", &output[bytes]);
        bytes++;
    }
    return bytes;
}

uint8_t* Read_Hex_File(const char *filename, size_t *data_len) {
    long file_len;
    char *content = Read_File(filename, &file_len);
    if (!content) {
        *data_len = 0;
        return NULL;
    }
    uint8_t *data = malloc(file_len / 2 + 1);
    if (!data) {
        free(content);
        *data_len = 0;
        return NULL;
    }
    *data_len = Convert_from_Hex(data, content, file_len / 2 + 1);
    free(content);
    if (*data_len == 0) {
        free(data);
        return NULL;
    }
    return data;
}

void Write_File(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot write to %s\n", filename);
        return;
    }
    fputs(content, file);
    fclose(file);
}

void Convert_to_Hex(char *output, const uint8_t *input, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sprintf(output + 2 * i, "%02X", input[i]);
    }
    output[len * 2] = '\0';
}

void Write_Hex_File(const char *filename, const uint8_t *data, size_t len) {
    char *hex_str = malloc(len * 2 + 1);
    if (!hex_str) return;
    Convert_to_Hex(hex_str, data, len);
    Write_File(filename, hex_str);
    free(hex_str);
}

void XOR_Bytes(uint8_t *output, const uint8_t *b1, const uint8_t *b2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        output[i] = b1[i] ^ b2[i];
    }
}

int Compute_SHA256(const uint8_t *data, size_t data_len, uint8_t *hash_output) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    unsigned int hash_len = 0;
    if (!mdctx) return 0;
    if (1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) ||
        1 != EVP_DigestUpdate(mdctx, data, data_len) ||
        1 != EVP_DigestFinal_ex(mdctx, hash_output, &hash_len)) {
        EVP_MD_CTX_free(mdctx);
        return 0;
    }
    EVP_MD_CTX_free(mdctx);
    return hash_len == SHA256_DIGEST_LENGTH;
}

// Read a hex file and require an exact decoded length
static uint8_t* read_exact(const char *file, size_t expected, const char *what) {
    size_t n = 0;
    uint8_t *d = Read_Hex_File(file, &n);
    if (!d) {
        fprintf(stderr, "Error: could not read %s (%s)\n", what, file);
        return NULL;
    }
    if (n != expected) {
        fprintf(stderr, "Error: %s has wrong length (%zu, expected %zu)\n", what, n, expected);
        free(d);
        return NULL;
    }
    return d;
}

// main

int main(int argc, char *argv[]) {
    if (argc != 6 && argc != 4) {
        fprintf(stderr, "Usage: %s bob_dilithium_public.txt alice_kyber_private.txt "
                        "bob_dilithium_signature.txt bob_kyber_ciphertext.txt k1_ab.txt\n", argv[0]);
        return 1;
    }

    int rc = 1;
    OQS_KEM *kem = NULL;
    OQS_SIG *sig = NULL;
    uint8_t *k1 = NULL, *bob_pk = NULL, *alice_sk = NULL;
    uint8_t *signature = NULL, *ct = NULL, *k2 = NULL, *xored = NULL;
    uint8_t final_key[SHA256_DIGEST_LENGTH];

    kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!kem || !sig) {
        fprintf(stderr, "Error: Kyber512 or Dilithium2 is not enabled in this liboqs build\n");
        goto cleanup;
    }

    const char *sig_file = "bob_dilithium_signature.txt";
    const char *ct_file = "bob_kyber_ciphertext.txt";

    if (argc == 6) {
        // Fixed argument order, as in VerifyPQTLS_P2.sh
        sig_file = argv[3];
        ct_file = argv[4];
        bob_pk = read_exact(argv[1], sig->length_public_key, "Bob's Dilithium public key");
        alice_sk = read_exact(argv[2], kem->length_secret_key, "Alice's Kyber private key");
        k1 = read_exact(argv[5], kem->length_shared_secret, "K1");
        if (!bob_pk || !alice_sk || !k1) goto cleanup;
    } else {
        // Three key files in any order, identified by length
        for (int i = 1; i < argc; i++) {
            size_t n = 0;
            uint8_t *d = Read_Hex_File(argv[i], &n);
            if (!d) {
                fprintf(stderr, "Error: could not read %s\n", argv[i]);
                goto cleanup;
            }
            if (n == kem->length_shared_secret && !k1) {
                k1 = d;
            } else if (n == sig->length_public_key && !bob_pk) {
                bob_pk = d;
            } else if (n == kem->length_secret_key && !alice_sk) {
                alice_sk = d;
            } else {
                fprintf(stderr, "Error: %s has an unexpected or duplicate size (%zu bytes)\n", argv[i], n);
                free(d);
                goto cleanup;
            }
        }
        if (!k1 || !bob_pk || !alice_sk) {
            fprintf(stderr, "Error: need K1, Bob's Dilithium public key and Alice's Kyber private key\n");
            goto cleanup;
        }
    }

    // Signature and ciphertext (lengths must match liboqs exactly)
    signature = read_exact(sig_file, sig->length_signature, "signature");
    if (!signature) goto cleanup;
    ct = read_exact(ct_file, kem->length_ciphertext, "ciphertext");
    if (!ct) goto cleanup;

    // Verify, abort BEFORE decapsulating or deriving anything if invalid
    if (OQS_SIG_verify(sig, ct, kem->length_ciphertext, signature, sig->length_signature, bob_pk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: signature verification FAILED, aborting\n");
        goto cleanup;
    }

    // Decapsulate to get K2
    k2 = malloc(kem->length_shared_secret);
    xored = malloc(kem->length_shared_secret);
    if (!k2 || !xored) {
        fprintf(stderr, "Error: out of memory\n");
        goto cleanup;
    }
    if (OQS_KEM_decaps(kem, k2, ct, alice_sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: decapsulation failed\n");
        goto cleanup;
    }
    // Write both.
    Write_Hex_File("k2_alice.txt", k2, kem->length_shared_secret);
    Write_Hex_File("alice_k2.txt", k2, kem->length_shared_secret);

    // Final key = SHA-256(K1 xor K2)
    XOR_Bytes(xored, k1, k2, kem->length_shared_secret);
    if (!Compute_SHA256(xored, kem->length_shared_secret, final_key)) {
        fprintf(stderr, "Error: SHA-256 failed\n");
        goto cleanup;
    }
    Write_Hex_File("alice_final_key.txt", final_key, SHA256_DIGEST_LENGTH);

    rc = 0;

cleanup:
    if (k2) { OQS_MEM_cleanse(k2, kem->length_shared_secret); free(k2); }
    if (xored) { OQS_MEM_cleanse(xored, kem->length_shared_secret); free(xored); }
    if (alice_sk) { OQS_MEM_cleanse(alice_sk, kem->length_secret_key); free(alice_sk); }
    free(k1);
    free(bob_pk);
    free(signature);
    free(ct);
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return rc;
}
