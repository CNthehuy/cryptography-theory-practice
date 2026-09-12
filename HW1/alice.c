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
    
    if(argc != 5) {
        return 1;
    }

    //T1: Read message, Key, Counter state, Nonce state
    int MessageLen;
    unsigned char *Message = Read_File(argv[1], &MessageLen);

    int KeyLen;
    unsigned char *Key = Read_File(argv[2], &KeyLen);
    
    int CounterLen;
    unsigned char *CounterA = Read_File(argv[3], &CounterLen);

    int NonceLen;
    unsigned char *NonceA = Read_File(argv[4], &NonceLen);


    //T2: Write key into hex format to a file named Key.txt
    char HexKey[(KeyLen * 2) + 1];
    Convert_to_Hex(HexKey, Key, KeyLen);
    Write_File("Key.txt", HexKey);


    //T3: Encrypts the message with XOR to attain the ciphertext: c ←m ⊕ H(k||ctr)
    unsigned char *ConcateKC = malloc(KeyLen + CounterLen);
    Concatenation(Key, KeyLen, CounterA, CounterLen, ConcateKC, KeyLen + CounterLen);

    unsigned char *Hash = Hash_Blake2s(ConcateKC, KeyLen + CounterLen);
    unsigned char *CipherText = malloc(MessageLen);

    for(int i = 0; i < MessageLen; i++) {
        CipherText[i] = Hash[i] ^ Message[i]; //XOR every byte
    }


    //T4: Writes the ciphertext in Hex format to a file named “Ciphertext.txt”.
    char HexCipherText[(MessageLen * 2) + 1];
    Convert_to_Hex(HexCipherText, CipherText, MessageLen);
    Write_File("Ciphertext.txt", HexCipherText);


    //T5: Computes the signature using a keyed HMAC: (sig ←HMACk(c||nonce)).
    unsigned char *ConcateCN = malloc(MessageLen + NonceLen);
    Concatenation(CipherText, MessageLen, NonceA, NonceLen, ConcateCN, MessageLen + NonceLen);

    unsigned char* Signature = malloc(32);
    unsigned int SignatureLen;
    HMAC_SHA256(Key, KeyLen, ConcateCN, MessageLen + NonceLen, Signature, &SignatureLen);

    
    //T6: Writes the signature in Hex format to a file named “Signature.txt”.
    char HexSignature[(SignatureLen * 2) + 1];
    Convert_to_Hex(HexSignature, Signature, SignatureLen);
    Write_File("Signature.txt", HexSignature);


    //T7: Once Bob has processed the message, Alice reads Bob’s response from the file named “Response.txt”.
    int ResponseLen;
    unsigned char* Response = Read_File("Response.txt", &ResponseLen);
    if(Response == NULL) { return 0;}

    //T8: Alice computes what the correct response should be from Bob (response′←H(m||(ctr + 1)||(nonce + 1))) and
    // compares it with Bob’s response (Note that Bob wrote the response in Hex format).

    //Transfer bob's response to char
    int CharResponseLen = ResponseLen / 2;
    unsigned char* CharResponse = malloc(CharResponseLen);
    Convert_To_Uchar((char *)Response, CharResponse, CharResponseLen);

    //Compute ctr + 1 and nonce + 1
    unsigned char* CounterInc = malloc(CounterLen + 2);
    memcpy(CounterInc, CounterA, CounterLen);
    CounterInc[CounterLen] = '\0';
    Increment(CounterInc, CounterLen);
    CounterLen = strlen((char *)CounterInc);

    unsigned char* NonceInc = malloc(NonceLen + 2);
    memcpy(NonceInc, NonceA, NonceLen);
    NonceInc[NonceLen] = '\0';
    Increment(NonceInc, NonceLen);
    NonceLen = strlen((char *)NonceInc);

    // Compute (m||(ctr + 1)||(nonce + 1))
    int ResponseInputSize = MessageLen + CounterLen + NonceLen;
    unsigned char* ConcateResponse = malloc(ResponseInputSize);
    unsigned char* temp = malloc(MessageLen + CounterLen);
    Concatenation(Message, MessageLen, CounterInc, CounterLen, temp, MessageLen + CounterLen);
    Concatenation(temp, MessageLen + CounterLen, NonceInc, NonceLen, ConcateResponse, ResponseInputSize);

    //Compute (response′←H(m||(ctr + 1)||(nonce + 1)))
    unsigned char* CorrectResponse =  Hash_Blake2s(ConcateResponse, ResponseInputSize);

    //Comparing correct response and bob's response
    int flag = 1;
    for(int i = 0; i < 32; i++) {
        if(CorrectResponse[i] != CharResponse[i]) {
            flag = 0;
            break;
        }
    }


    //T9: If the comparison is successful, Alice writes “Acknowledgment Successful” in a file 
    // called “Acknowledg-ment.txt.” Conversely, if the comparison fails, she records “Acknowledgment Failed.”
    if(flag == 1) {
        Write_File("Acknowledgment.txt","Acknowledgment Successful");
    }
    else {
        Write_File("Acknowledgment.txt","Acknowledgment Failed");
    }
    
    //10: Alice increments and updates her counter and nonce files “A_ctr.txt” and “A_nonce.txt”.
    Write_File("A_ctr.txt", CounterInc);
    Write_File("A_nonce.txt", NonceInc);



    return 0;
}