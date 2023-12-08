#include <stdio.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#define KEY_LENGTH 2048

void generate_key_pair(RSA **private_key, RSA **public_key) {
    *private_key = RSA_generate_key(KEY_LENGTH, RSA_F4, NULL, NULL);
    *public_key = RSAPublicKey_dup(*private_key);
}

void encrypt_message(const char *message, const RSA *public_key, unsigned char **encrypted_message, size_t *encrypted_len) {
    *encrypted_message = (unsigned char *)malloc(RSA_size(public_key));
    *encrypted_len = RSA_public_encrypt(strlen(message) + 1, (const unsigned char *)message, *encrypted_message, public_key, RSA_PKCS1_OAEP_PADDING);
}

void decrypt_message(const unsigned char *encrypted_message, size_t encrypted_len, const RSA *private_key, char **decrypted_message) {

printf("Encrypted Message: %s\n", encrypted_message);  
    printf("Encrypted Length: %zu\n", encrypted_len);
    printf("Decrypted Message within the function: %s\n", *decrypted_message); 
    
    printf("Decrypted Message within the private_key: %s\n", private_key); 
    *decrypted_message = (char *)malloc(RSA_size(private_key));
    RSA_private_decrypt(encrypted_len, encrypted_message, (unsigned char *)*decrypted_message, private_key, RSA_PKCS1_OAEP_PADDING);
}



int main() {
    RSA *alice_private_key, *alice_public_key;
    RSA *bob_private_key, *bob_public_key;

    generate_key_pair(&alice_private_key, &alice_public_key);
    generate_key_pair(&bob_private_key, &bob_public_key);
printf("Alice pk", alice_private_key);
    	printf("\n");
    	printf("Alice puk", alice_public_key);
    	printf("bob");
    	printf(bob_private_key);
    	printf(bob_public_key);
    // Alice's side
    const char *alice_message = "Hello Bob, it's Alice!";
    unsigned char *alice_encrypted_message;
    size_t alice_encrypted_len;
    encrypt_message(alice_message, bob_public_key, &alice_encrypted_message, &alice_encrypted_len);

    // Bob's side
    printf(alice_encrypted_message);
    char *bob_decrypted_message;
    printf("alice_encrypted_message length: %zu\n", alice_encrypted_len);
    printf("alice_encrypted_message content: %s\n", alice_encrypted_message);
    printf("bob pk: %s\n", bob_private_key);
    printf("bob dec me: %s\n", bob_decrypted_message);
    decrypt_message(alice_encrypted_message, alice_encrypted_len, bob_private_key, &bob_decrypted_message);

    printf("bob pk: %s\n", bob_private_key);
    printf("bob dec me: %s\n", bob_decrypted_message);
    // Verify identity
    printf("Bob received and decrypted: '%s'\n", bob_decrypted_message);

    // Cleanup
    RSA_free(alice_private_key);
    RSA_free(alice_public_key);
    RSA_free(bob_private_key);
    RSA_free(bob_public_key);
    free(alice_encrypted_message);
    free(bob_decrypted_message);

    return 0;
}

