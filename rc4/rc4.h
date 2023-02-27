/**
 * Implementation of the RC4 stream cipher algorithm
 */

typedef struct __rc4_state {
    unsigned char i;
    unsigned char n;
    unsigned char s[256];
} rc4_state;

/**
 * initializes the RC4 state - this is needed before starting en/decryption
 */
void rc4_init(rc4_state* state, unsigned char* key, unsigned int keylen);

/**
 * en/decrypts the given data
 */
void rc4_crypt(rc4_state* state, unsigned char* data, unsigned int datalen);
