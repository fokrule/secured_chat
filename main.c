#include <stdio.h>
#include "dh.h"

int main() {
    if (init("params") == 0) {
        printf("Successfully read DH params.\n");
    }

    mpz_t sk, pk;
    mpz_inits(sk, pk, NULL);
printf("Before mpz_mod:\n");
printf("sk: ");
mpz_out_str(stdout, 10, sk);
printf("\na: ");
mpz_out_str(stdout, 10, pk);
printf("\nq: ");
    if (dhGen(sk, pk) == 0) {
        gmp_printf("Generated key pair: ");
    } else {
        fprintf(stderr, "Error generating key pair.\n");
    }

    mpz_clears(sk, pk, NULL);

    return 0;
}

