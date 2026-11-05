#include <stdio.h>
#include "ccs.h"

int main(void) {
    const ccs_chacha_key_t key = { 1 }; // Example only. Use a securely generated secret key.
    const ccs_chacha_ietf_nonce_t nonce = { 0 }; // Never reuse a nonce with the same key for encryption.
    const uint8_t plaintext[] = "Hello World";
    const uint8_t ad[] = "Example header"; // Authenticated, but not encrypted.
    
    uint8_t ciphertext[sizeof(plaintext)];
    ccs_poly1305_digest_t tag;
    ccs_res_t res = ccs_chacha20_poly1305_ietf_encrypt(key, nonce, sizeof(plaintext), plaintext, sizeof(ad) - 1, ad, ciphertext, tag);
    if(res != CCS_OK)
        return 1;

    uint8_t decrypted[sizeof(plaintext)];
    // Output will only be decrypted if the tag verifies.
    res = ccs_chacha20_poly1305_ietf_decrypt(key, nonce, tag, sizeof(ciphertext), ciphertext, sizeof(ad) - 1, ad, decrypted);
    if(res != CCS_OK)
        return 1;

    printf("%s\n", (const char*)decrypted);

    return 0;
}
