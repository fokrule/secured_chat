#include "dh.h"
#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>



#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


#include "handshake.h"
//#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

// Define the size of the shared secret key
#define KEY_SIZE 128
// Declare missing functions




void generateEphemeralKeyPair(mpz_t sk, mpz_t pk) {
    dhGen(sk, pk);
}

void deriveSharedSecret(mpz_t ownSecretKey, mpz_t ownPublicKey, mpz_t otherPublicKey, unsigned char* sharedSecret, size_t keySize) {
    dhFinal(ownSecretKey, ownPublicKey, otherPublicKey, sharedSecret, keySize);
}

void handshakeProtocol() {
    // Alice's setup
    // Alice's setup
    mpz_t aliceSecretKey, alicePublicKey;
    mpz_init(aliceSecretKey);
    mpz_init(alicePublicKey);
    generateEphemeralKeyPair(aliceSecretKey, alicePublicKey);

    // Bob's setup
    mpz_t bobSecretKey, bobPublicKey;
    mpz_init(bobSecretKey);
    mpz_init(bobPublicKey);
    generateEphemeralKeyPair(bobSecretKey, bobPublicKey);

    // Alice sends her public key to Bob
    // Bob receives Alice's public key

 // Alice sends her public key to Bob
    // Bob receives Alice's public key

    // Bob sends his public key to Alice
    // Alice receives Bob's public key

    // Both parties derive the shared secret
    unsigned char aliceSharedSecret[KEY_SIZE];
    unsigned char bobSharedSecret[KEY_SIZE];

    deriveSharedSecret(aliceSecretKey, alicePublicKey, bobPublicKey, aliceSharedSecret, KEY_SIZE);
    deriveSharedSecret(bobSecretKey, bobPublicKey, alicePublicKey, bobSharedSecret, KEY_SIZE);

    // Verify that both parties have the same shared secret
    if (memcmp(aliceSharedSecret, bobSharedSecret, KEY_SIZE) == 0) {
        printf("Handshake successful! Shared secret established with perfect forward secrecy.\n");
        
   } else {
      printf("Handshake failed!\n");
  }
    // Clean up resources
    mpz_clears(aliceSecretKey, alicePublicKey, bobSecretKey, bobPublicKey, NULL);
    //return ;
}

//int main() {
 // if (init("params") == 0) {
 //       printf("Successfully read DH params.\n");
  //  }

  //  handshakeProtocol();

   // return 0;
//}

