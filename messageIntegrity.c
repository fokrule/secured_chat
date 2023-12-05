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

// Function to verify HMAC of a message
int verifyHMAC(const unsigned char* key, size_t key_length, const unsigned char* message, size_t message_length, const unsigned char* received_hmac) {
    unsigned char calculated_hmac[EVP_MAX_MD_SIZE];
    calculateHMAC(key, key_length, message, message_length, calculated_hmac);

    // Compare the calculated HMAC with the received HMAC
    if (memcmp(calculated_hmac, received_hmac, EVP_MAX_MD_SIZE) == 0) {
        return 1; // HMAC verification successful
    } else {
        return 0; // HMAC verification failed
    }
}

// Modify the sendMessage function to include HMAC
static void sendMessage(GtkWidget* w, gpointer)
{
   

    // Generate a random secret key for HMAC
    unsigned char hmac_key[EVP_MAX_KEY_LENGTH];
    generateHMACKey(hmac_key, EVP_MAX_KEY_LENGTH);

    

   
}