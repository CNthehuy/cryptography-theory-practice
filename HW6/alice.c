#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include <oqs/oqs.h>

// helper functions

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

// main

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s bob_kyber_public.txt alice_dilithium_private.txt\n", argv[0]);
        return 1;
    }

    int rc = 1;
    OQS_KEM *kem = NULL;
    OQS_SIG *sig = NULL;
    uint8_t *bob_pk = NULL, *alice_sk = NULL;
    uint8_t *ct = NULL, *ss = NULL, *signature = NULL;
    size_t bob_pk_len = 0, alice_sk_len = 0, sig_len = 0;

    kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!kem || !sig) {
        fprintf(stderr, "Error: Kyber512 or Dilithium2 is not enabled in this liboqs build\n");
        goto cleanup;
    }

    // Read keys and check lengths
    bob_pk = Read_Hex_File(argv[1], &bob_pk_len);
    if (!bob_pk) {
        fprintf(stderr, "Error: could not read Bob's Kyber public key\n");
        goto cleanup;
    }
    if (bob_pk_len != kem->length_public_key) {
        fprintf(stderr, "Error: Kyber public key has wrong length (%zu, expected %zu)\n",
                bob_pk_len, kem->length_public_key);
        goto cleanup;
    }

    alice_sk = Read_Hex_File(argv[2], &alice_sk_len);
    if (!alice_sk) {
        fprintf(stderr, "Error: could not read Alice's Dilithium private key\n");
        goto cleanup;
    }
    if (alice_sk_len != sig->length_secret_key) {
        fprintf(stderr, "Error: Dilithium secret key has wrong length (%zu, expected %zu)\n",
                alice_sk_len, sig->length_secret_key);
        goto cleanup;
    }

    ct = malloc(kem->length_ciphertext);
    ss = malloc(kem->length_shared_secret);
    signature = malloc(sig->length_signature);
    if (!ct || !ss || !signature) {
        fprintf(stderr, "Error: out of memory\n");
        goto cleanup;
    }

    // (CT_A, K1_A) = Kyber.Encaps(pk_KB)
    if (OQS_KEM_encaps(kem, ct, ss, bob_pk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: encapsulation failed\n");
        goto cleanup;
    }

    // Sigma_A = Dilithium.Sign(sk_DA, CT_A)
    if (OQS_SIG_sign(sig, signature, &sig_len, ct, kem->length_ciphertext, alice_sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: signing failed\n");
        goto cleanup;
    }

    // Write outputs
    Write_Hex_File("kyber_ciphertext.txt", ct, kem->length_ciphertext);
    Write_Hex_File("dilithium_signature.txt", signature, sig_len);
    Write_Hex_File("alice_shared_secret.txt", ss, kem->length_shared_secret);

    rc = 0;

cleanup:
    if (ss) { OQS_MEM_cleanse(ss, kem->length_shared_secret); free(ss); }
    if (alice_sk) { OQS_MEM_cleanse(alice_sk, alice_sk_len); free(alice_sk); }
    free(bob_pk);
    free(ct);
    free(signature);
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return rc;
}
