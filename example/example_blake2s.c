#include <stdio.h>
#include "ccs.h"

int main(void) {
    const ccs_blake2s_key_t key = { 1 }; // Example only. Use a securely generated secret key.
    const ccs_blake2s_salt_t salt = { 2 };
    const ccs_blake2s_personal_t personal = { 3 };
    const uint8_t message[] = "Hello World";
    
    ccs_blake2s_ctx_t ctx;
    ccs_blake2s_digest_t digest;
    ccs_res_t res = ccs_blake2s_init(&ctx, sizeof(digest));
    if(res != CCS_OK)
        return 1;

    ccs_blake2s_config_key(&ctx, key);           // (Optional) Set a key for keyed BLAKE2
    ccs_blake2s_config_salt(&ctx, salt);         // (Optional) Configure salt field
    ccs_blake2s_config_personal(&ctx, personal); // (Optional) Configure personalization field

    ccs_blake2s_update(&ctx, sizeof(message) - 1, message);
    
    ccs_blake2s_final(&ctx, digest);

    for(size_t i = 0; i < sizeof(digest); i++)
        printf("%02x", (unsigned int)digest[i]);
    printf("\n");

    return 0;
}
