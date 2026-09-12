#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "RequiredFunctionsHW1.h"

//Function built for incrementing counter and nonce
void Increment(unsigned char *value, int len)
{
    int i = len - 1;
    while (i >= 0 && value[i] == '9') {
        value[i] = '0';
        i--;
    }
    if (i >= 0) {
        value[i]++;
    }
    else {
        // All digits were 9
        memmove(value + 1, value, len);
        value[0] = '1';
        value[len + 1] = '\0';
    }
}

int main(int argc, char *argv[]) {

    if (argc != 6) {
        return 1;
    }

    //T1: Bob reads the ciphertext, signature, shared secret key, his counter state, and his nonce state from "Ciphertext.txt", "Signature.txt", "SharedKey.txt", "B_ctr.txt", and "B_nonce.txt" respectively.
    int HexCipherLen;
    unsigned char* HexCipherText = Read_File(argv[1], &HexCipherLen);

    int SignatureLen;
    unsigned char* Signature = Read_File(argv[2], &SignatureLen);

    int KeyLen;
    unsigned char* Key = Read_File(argv[3], &KeyLen);

    int CounterLen;
    unsigned char* CounterB = Read_File(argv[4], &CounterLen);

    int NonceLen;
    unsigned char* NonceB = Read_File(argv[5], &NonceLen);


    //T2: Bob computes the expected signature using a keyed HMAC in the same manner as Alice ((sig'←HMACk(c||nonce)))
    // and checks it against the signature that Alice provided (Note that Alice wrote the signature in Hex format).
    
    //Transfer Ciphertext to char
    int CipherLen = HexCipherLen / 2;
    unsigned char* CipherText = malloc(CipherLen);
    Convert_To_Uchar((char *)HexCipherText,CipherText, CipherLen);

    //Change Alice's Sig to char
    unsigned char *ConcateCN = malloc(CipherLen + NonceLen);
    Concatenation(CipherText, CipherLen, NonceB, NonceLen, ConcateCN, CipherLen + NonceLen);

    int CharSigLen = SignatureLen / 2;
    unsigned char* CharSig = malloc(CharSigLen);
    Convert_To_Uchar((char *)Signature, CharSig, CharSigLen);

    unsigned char* SigNew = malloc(32);
    unsigned int SigNewLen;
    HMAC_SHA256(Key, KeyLen, ConcateCN, CipherLen + NonceLen, SigNew, &SigNewLen);
    //Comparing the signatures
    int flag = 1;
    for(int i = 0; i < 32; i++) {
        if(CharSig[i] != SigNew[i]) {
            flag = 0;
            break;
        }
    }


    //T3: If the comparison is successful, Bob continues, otherwise the program exits.
    if(flag == 0) {exit(0);}


    //T4: Bob decrypts the ciphertext with XOR: m ←c ⊕H(k||ctr).
    unsigned char *ConcateKC = malloc(KeyLen + CounterLen);
    Concatenation(Key, KeyLen, CounterB, CounterLen, ConcateKC, KeyLen + CounterLen);

    unsigned char *Hash = malloc(32);
    SHA256(ConcateKC, KeyLen + CounterLen, Hash);
    unsigned char *Message = malloc(CipherLen);

    for(int i = 0; i < CipherLen; i++) {
       Message[i] = Hash[i] ^ CipherText[i]; //XOR every byte
    }

    //T5: Bob computes his response: response ←H(m||(ctr + 1)||(nonce + 1)).

    //Compute ctr + 1 and nonce + 1
    unsigned char* CounterInc = malloc(CounterLen + 2);
    memcpy(CounterInc, CounterB, CounterLen);
    CounterInc[CounterLen] = '\0';
    Increment(CounterInc, CounterLen);
    CounterLen = strlen((char *)CounterInc);

    unsigned char* NonceInc = malloc(NonceLen + 2);
    memcpy(NonceInc, NonceB, NonceLen);
    NonceInc[NonceLen] = '\0';
    Increment(NonceInc, NonceLen);
    NonceLen = strlen((char *)NonceInc);

    // Compute (m||(ctr + 1)||(nonce + 1))
    int ResponseSize = CipherLen + CounterLen + NonceLen;
    unsigned char* ConcateResponse = malloc(ResponseSize);
    unsigned char* temp = malloc(CipherLen + CounterLen);
    Concatenation(Message, CipherLen, CounterInc, CounterLen, temp, CipherLen + CounterLen);
    Concatenation(temp, CipherLen + CounterLen, NonceInc, NonceLen, ConcateResponse, ResponseSize);

    //Compute H(m||(ctr + 1)||(nonce + 1))
    unsigned char* Response = malloc(32);
    SHA256(ConcateResponse, ResponseSize, Response);


    //T6: Bob writes his response in Hex format to a file named "Response.txt".
    char HexResponse[(32 * 2) + 1];
    Convert_to_Hex(HexResponse, Response, 32);
    Write_File("Response.txt", HexResponse);


    //T7: Bob increments and updates his counter and nonce files "B_ctr.txt" and "B_nonce.txt".
    Write_File("B_ctr.txt", (char *)CounterInc);
    Write_File("B_nonce.txt", (char *)NonceInc);
    
    
    return 0;
}
