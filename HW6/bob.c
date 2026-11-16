/*
    HW6 Part 1 - Bob: Dilithium2 signature verification + Kyber512 decapsulation
    Usage: ./bob alice_dilithium_public.txt bob_kyber_private.txt
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#include <oqs/oqs.h>

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

// ---- main ----

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s alice_dilithium_public.txt bob_kyber_private.txt\n", argv[0]);
        return 1;
    }

    int rc = 1;
    OQS_KEM *kem = NULL;
    OQS_SIG *sig = NULL;
    uint8_t *alice_pk = NULL, *bob_sk = NULL, *signature = NULL, *ct = NULL, *ss = NULL;
    size_t alice_pk_len = 0, bob_sk_len = 0, signature_len = 0, ct_len = 0;

    kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (!kem || !sig) {
        fprintf(stderr, "Error: Kyber512 or Dilithium2 is not enabled in this liboqs build\n");
        goto cleanup;
    }

    // Steps 1-2: read keys and check lengths
    alice_pk = Read_Hex_File(argv[1], &alice_pk_len);
    if (!alice_pk) {
        fprintf(stderr, "Error: could not read Alice's Dilithium public key\n");
        goto cleanup;
    }
    if (alice_pk_len != sig->length_public_key) {
        fprintf(stderr, "Error: Dilithium public key has wrong length (%zu, expected %zu)\n",
                alice_pk_len, sig->length_public_key);
        goto cleanup;
    }

    bob_sk = Read_Hex_File(argv[2], &bob_sk_len);
    if (!bob_sk) {
        fprintf(stderr, "Error: could not read Bob's Kyber private key\n");
        goto cleanup;
    }
    if (bob_sk_len != kem->length_secret_key) {
        fprintf(stderr, "Error: Kyber secret key has wrong length (%zu, expected %zu)\n",
                bob_sk_len, kem->length_secret_key);
        goto cleanup;
    }

    // Steps 3-4: read signature and ciphertext, check lengths
    signature = Read_Hex_File("dilithium_signature.txt", &signature_len);
    if (!signature) {
        fprintf(stderr, "Error: could not read dilithium_signature.txt\n");
        goto cleanup;
    }
    if (signature_len != sig->length_signature) {
        fprintf(stderr, "Error: signature has wrong length (%zu, expected %zu)\n",
                signature_len, sig->length_signature);
        goto cleanup;
    }

    ct = Read_Hex_File("kyber_ciphertext.txt", &ct_len);
    if (!ct) {
        fprintf(stderr, "Error: could not read kyber_ciphertext.txt\n");
        goto cleanup;
    }
    if (ct_len != kem->length_ciphertext) {
        fprintf(stderr, "Error: ciphertext has wrong length (%zu, expected %zu)\n",
                ct_len, kem->length_ciphertext);
        goto cleanup;
    }

    // Step 5: verify signature over the ciphertext; abort BEFORE decapsulating if invalid
    if (OQS_SIG_verify(sig, ct, ct_len, signature, signature_len, alice_pk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: signature verification FAILED, aborting\n");
        goto cleanup;
    }

    // Step 6: decapsulate
    ss = malloc(kem->length_shared_secret);
    if (!ss) {
        fprintf(stderr, "Error: out of memory\n");
        goto cleanup;
    }
    if (OQS_KEM_decaps(kem, ss, ct, bob_sk) != OQS_SUCCESS) {
        fprintf(stderr, "Error: decapsulation failed\n");
        goto cleanup;
    }
    Write_Hex_File("bob_shared_secret.txt", ss, kem->length_shared_secret);

    rc = 0;

cleanup:
    if (ss) { OQS_MEM_cleanse(ss, kem->length_shared_secret); free(ss); }
    if (bob_sk) { OQS_MEM_cleanse(bob_sk, bob_sk_len); free(bob_sk); }
    free(alice_pk);
    free(signature);
    free(ct);
    if (kem) OQS_KEM_free(kem);
    if (sig) OQS_SIG_free(sig);
    return rc;
}
