#include "rc4.h"

#define SWAP(A, B)     \
  {                    \
    unsigned char tmp; \
    tmp = A;           \
    A = B;             \
    B = tmp;           \
  }

void rc4_init(rc4_state* state, unsigned char* key, unsigned int keylen) {
  unsigned int i;
  unsigned char n = 0;

  for (i = 0; i < 256; i++) state->s[i] = i;

  for (i = 0; i < 256; i++) {
    n += state->s[i] + key[i % keylen];
    SWAP(state->s[i], state->s[n])
  }
  state->i = 0;
  state->n = 0;
}

void rc4_crypt(rc4_state* state, unsigned char* data, unsigned int datalen) {
  unsigned int i;

  for (i = 0; i < datalen; i++) {
    unsigned char z;

    state->i += 1;
    state->n += state->s[state->i];
    SWAP(state->s[state->i], state->s[state->n])
    z = state->s[state->i] + state->s[state->n];
    z = state->s[z];
    data[i] ^= z;
  }
}
