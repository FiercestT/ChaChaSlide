#include <stdio.h>
#include "ccs.h"

int main(void) {
    const ccs_chacha_key_t key = { 1 }; // Example only. Use a securely generated secret key.
    const ccs_chacha_djb_nonce_t nonce = { 0 }; // Never reuse a nonce with the same key for encryption.
    const uint8_t plaintext[] = "Hello World";
    
    printf("Plaintext: %s\n", (const char*)plaintext);
    
    uint8_t ciphertext[sizeof(plaintext)];

    // 12 Rounds, start ctr at 0. 
    ccs_res_t res = ccs_chachaN_djb(12, 0, key, nonce, sizeof(plaintext), plaintext, ciphertext);
    if(res != CCS_OK)
        return 1;

    printf("Ciphertext (hex): ");
    for(size_t i = 0; i < sizeof(ciphertext); i++)
        printf("%02x", (unsigned int)ciphertext[i]);
    printf("\n");

    // Decrypt in place (in buffer = out buffer)
    res = ccs_chachaN_djb(12, 0, key, nonce, sizeof(ciphertext), ciphertext, ciphertext);
    if(res != CCS_OK)
        return 1;

    printf("Decrypted: %s\n", (const char*)ciphertext);

    return 0;
}
