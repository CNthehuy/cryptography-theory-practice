/*
    HW6 Part 2 - Bob: Kyber512 encapsulation to Alice, Dilithium2 signing,
    final key H(K1 xor K2) with SHA-256.

    Accepted calls (the three files are identified by their decoded size, so either order works):
      ./bobxor bob_dilithium_private.txt alice_kyber_public.txt k1_ab.txt     (VerifyPQTLS_P2.sh)
      ./bobxor k1_ab.txt alice_kyber_public.txt bob_dilithium_private.txt     (handout text)
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

// ---- helper functions (from PQTLSfunctions.c) ----

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

// ---- main ----

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s bob_dilithium_private.txt alice_kyber_public.txt k1_ab.txt\n", argv[0]);
        return 1;
    }

    int rc = 1;
    OQS_KEM *kem = NULL;
    OQS_SIG *sig = NULL;
    uint8_t *k1 = NULL, *alice_pk = NULL, *bob_sk = NULL;
    uint8_t *ct = NULL, *k2 = NULL, *signature = NULL, *xored = NULL;
    uint8_t final_key[SHA256_DIGEST_LENGTH];
    size_t bob_sk_len = 0, sig_len = 0;

    kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!kem || !sig) {
        fprintf(stderr, "Error: Kyber512 or Dilithium2 is not enabled in this liboqs build\n");
        goto cleanup;
    }

    // Read the three inputs and identify each by its length (this also validates the lengths)
    for (int i = 1; i < argc; i++) {
        size_t n = 0;
        uint8_t *d = Read_Hex_File(argv[i], &n);
        if (!d) {
            fprintf(stderr, "Error: could not read %s\n", argv[i]);
            goto cleanup;
        }
        if (n == kem->length_shared_secret && !k1) {
            k1 = d;
        } else if (n == kem->length_public_key && !alice_pk) {
            alice_pk = d;
        } else if (n == sig->length_secret_key && !bob_sk) {
            bob_sk = d;
            bob_sk_len = n;
        } else {
            fprintf(stderr, "Error: %s has an unexpected or duplicate size (%zu bytes)\n", argv[i], n);
            free(d);
            goto cleanup;
        }
    }
    if (!k1 || !alice_pk || !bob_sk) {
        fprintf(stderr, "Error: need K1, Alice's Kyber public key and Bob's Dilithium private key\n");
        goto cleanup;
    }

    ct = malloc(kem->length_ciphertext);
    k2 = malloc(kem->length_shared_secret);
    signature = malloc(sig->length_signature);
    xored = malloc(kem->length_shared_secret);
    if (!ct || !k2 || !signature || !xored) {
        fprintf(stderr, "Error: out of memory\n");
        goto cleanup;
    }

    // (CT_B, K2_B) = Kyber.Encaps(pk_KA)
    if (OQS_KEM_encaps(kem, ct, k2, alice_pk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: encapsulation failed\n");
        goto cleanup;
    }

    // sigma_B = Dilithium.Sign(sk_DB, CT_B)
    if (OQS_SIG_sign(sig, signature, &sig_len, ct, kem->length_ciphertext, bob_sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: signing failed\n");
        goto cleanup;
    }

    // final key = SHA-256(K1 xor K2)
    XOR_Bytes(xored, k1, k2, kem->length_shared_secret);
    if (!Compute_SHA256(xored, kem->length_shared_secret, final_key)) {
        fprintf(stderr, "Error: SHA-256 failed\n");
        goto cleanup;
    }

    Write_Hex_File("bob_kyber_ciphertext.txt", ct, kem->length_ciphertext);
    Write_Hex_File("bob_dilithium_signature.txt", signature, sig_len);
    Write_Hex_File("bob_final_key.txt", final_key, SHA256_DIGEST_LENGTH);
    // The handout calls this file k2_bob.txt, the test script compares bob_k2.txt: write both.
    Write_Hex_File("k2_bob.txt", k2, kem->length_shared_secret);
    Write_Hex_File("bob_k2.txt", k2, kem->length_shared_secret);

    rc = 0;

cleanup:
    if (k2) { OQS_MEM_cleanse(k2, kem->length_shared_secret); free(k2); }
    if (xored) { OQS_MEM_cleanse(xored, kem->length_shared_secret); free(xored); }
    if (bob_sk) { OQS_MEM_cleanse(bob_sk, bob_sk_len); free(bob_sk); }
    free(k1);
    free(alice_pk);
    free(ct);
    free(signature);
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return rc;
}
