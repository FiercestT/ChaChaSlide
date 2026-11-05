#include <stdio.h>
#include "ccs.h"

int main(void) {
    const ccs_poly1305_key_t key = { 1 }; // Example only. Use a fresh secret key for each message.
    const uint8_t message[] = "Hello World";
    
    ccs_poly1305_ctx_t ctx;
    ccs_res_t res = ccs_poly1305_init(&ctx, key);
    if(res != CCS_OK)
        return 1;

    ccs_poly1305_update(&ctx, sizeof(message) - 1, message);
    
    ccs_poly1305_digest_t tag;
    ccs_poly1305_final(&ctx, tag);

    for(size_t i = 0; i < sizeof(tag); i++)
        printf("%02x", (unsigned int)tag[i]);
    printf("\n");

    return 0;
}
