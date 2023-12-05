#include <openssl/hmac.h>
#include <openssl/rand.h>

// Function to generate a random secret key for HMAC
void generateHMACKey(unsigned char* key, size_t key_length) {
    if (RAND_bytes(key, key_length) != 1) {
        perror("Error generating random key for HMAC");
        exit(EXIT_FAILURE);
    }
}

// Function to calculate HMAC of a message using a key
void calculateHMAC(const unsigned char* key, size_t key_length, const unsigned char* message, size_t message_length, unsigned char* hmac_result) {
    HMAC(EVP_sha256(), key, key_length, message, message_length, hmac_result, NULL);
}