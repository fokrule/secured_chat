#include <openssl/hmac.h>
#include <openssl/rand.h>

// Function to generate a random secret key for HMAC
void generateHMACKey(unsigned char* key, size_t key_length) {
    if (RAND_bytes(key, key_length) != 1) {
        perror("Error generating random key for HMAC");
        exit(EXIT_FAILURE);
    }
}