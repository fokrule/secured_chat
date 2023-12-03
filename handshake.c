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

void generateEphemeralKeyPair(mpz_t sk, mpz_t pk) {
 	//printf("sk30: ");
//mpz_out_str(stdout, 10, sk);  // Print mpz_t as a decimal string
//printf("\n");
//printf("pk40: ");
//mpz_out_str(stdout, 10, pk);  // Print mpz_t as a decimal string
//printf("\n");
    dhGen(sk, pk);
}

void deriveSharedSecret(mpz_t ownSecretKey, mpz_t ownPublicKey, mpz_t otherPublicKey, unsigned char* sharedSecret, size_t keySize) {
    dhFinal(ownSecretKey, ownPublicKey, otherPublicKey, sharedSecret, keySize);
}

//EVP_PKEY *generateRSAKeyPair() {
  //  EVP_PKEY *pkey = EVP_PKEY_new();
    //if (pkey == NULL) {
        // Handle error
      //  return NULL;
    //}

    // Set the key type to RSA
    //if (EVP_PKEY_set_type(pkey, EVP_PKEY_RSA) <= 0) {
        // Handle error
    //    EVP_PKEY_free(pkey);
   //     return NULL;
   // }

    // Create a new RSA key context
   // EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
   // if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        // Handle error
   //     EVP_PKEY_free(pkey);
   //     EVP_PKEY_CTX_free(ctx);
   //     return NULL;
   // }

    // Generate an RSA key pair
   // if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        // Handle error
  //      EVP_PKEY_free(pkey);
  //      EVP_PKEY_CTX_free(ctx);
   //     return NULL;
  //  }

    // Free the RSA key context
   // EVP_PKEY_CTX_free(ctx);

  //  return pkey;
//}
//void encryptAndSign(mpz_t privateKey, mpz_t publicKey, unsigned char* message, size_t msgSize, unsigned char* ciphertext, unsigned char* signature) {
    // Use RSA encryption and signing for simplicity
    // You may replace this with your chosen cryptographic library
//if (privateKey == NULL || publicKey == NULL || message == NULL || ciphertext == NULL || signature == NULL) {
    // Handle the error, log, or return an appropriate value
	//printf("null value found");
//}
    // RSA encryption
    //RSA* rsaKey = RSA_new();
  //  EVP_PKEY *evpKey = generateRSAKeyPair();
  //  if (evpKey == NULL) {
        // Handle error
   //     return;
   // }

    // Obtain the RSA key from the EVP_PKEY
    //const RSA *rsaKey = EVP_PKEY_get0_RSA(evpKey);
  //  if (rsaKey == NULL) {
        // Handle error
   //     EVP_PKEY_free(evpKey);
  //      return;
  //  }
  //  //printf("Key Size: %d bits\n", RSA_size(rsaKey) * 8);
    //return;
    // Load private key
    // RSA_set0_key(rsaKey, BN_new(), BN_dup(privateKey), NULL);
    // Use public key for simplicity, in practice use the recipient's public key
    //RSA_set0_key(rsaKey, BN_dup(publicKey), NULL, NULL);

//RSA_set0_key((RSA*)rsaKey, (BIGNUM*)publicKey, NULL, NULL);

//int encryptedSize = RSA_public_encrypt(msgSize, message, ciphertext, (RSA*)rsaKey, RSA_PKCS1_OAEP_PADDING);
    //int encryptedSize = RSA_public_encrypt(msgSize, message, ciphertext, rsaKey, RSA_PKCS1_OAEP_PADDING);
    //RSA_free(rsaKey);
//RSA_free((RSA*)rsaKey);

    // RSA signing
    // Use private key for simplicity, in practice use the sender's private key
    //RSA* rsaPrivateKey = RSA_new();
    
    //RSA_set0_key(rsaPrivateKey, NULL, BN_dup(privateKey), NULL);
  //  RSA_set0_key((RSA*)rsaKey, NULL, BN_dup((BIGNUM*)(RSA*)rsaKey), NULL);

   // unsigned int signatureSize;
   // int signedSize = RSA_sign(NID_sha256, message, msgSize, signature, &signatureSize, (RSA*)rsaKey);
   // RSA_free((RSA*)rsaKey);
   // EVP_PKEY_free(evpKey);
//}


//int verifySignature(mpz_t publicKey, unsigned char* message, size_t msgSize, unsigned char* signature) {
    // Use RSA verification for simplicity
    //RSA* rsaKey = RSA_new();
    
 //   EVP_PKEY *evpKey = generateRSAKeyPair();
    

    // Obtain the RSA key from the EVP_PKEY
   // const RSA *rsaKey = EVP_PKEY_get0_RSA(evpKey);
   // if (rsaKey == NULL) {
        // Handle error
   //     EVP_PKEY_free(evpKey);
   //     //return;
   // }
    //RSA_set0_key(rsaKey, BN_dup(publicKey), NULL, NULL);
   // RSA_set0_key((RSA*)rsaKey, BN_dup((BIGNUM*)(RSA*)rsaKey), NULL, NULL);
   // int result = RSA_verify(NID_sha256, message, msgSize, signature, KEY_SIZE, rsaKey);
   // RSA_free(rsaKey);
   // return result;
//}


//void decryptFunction(mpz_t privateKey, unsigned char* ciphertext, size_t ciphertextSize, unsigned char* decryptedMessage) {
    // Use the shared secret key derived from Diffie-Hellman as the AES key
  //  unsigned char aesKey[KEY_SIZE];
  //  deriveSharedSecret(privateKey, privateKey, privateKey, aesKey, KEY_SIZE);

    // Decrypt the message using AES
   // AES_KEY decryptKey;
   // AES_set_decrypt_key(aesKey, 128, &decryptKey);
   // AES_decrypt(ciphertext, decryptedMessage, &decryptKey);

    // Clean up
   // memset(aesKey, 0, KEY_SIZE);
//}








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
        
        
        // Encrypt and sign Alice's message
        //unsigned char aliceMessage[] = "Hello Bob!";
       // unsigned char aliceCiphertext[KEY_SIZE];
       // unsigned char aliceSignature[KEY_SIZE];
       // encryptAndSign(aliceSecretKey, alicePublicKey, aliceMessage, sizeof(aliceMessage), aliceCiphertext, aliceSignature);

        // Send Alice's encrypted message and signature to Bob
        // Bob receives Alice's message and verifies the signature
       // if (verifySignature(bobPublicKey, aliceMessage, sizeof(aliceMessage), aliceSignature)) {
            // Signature verification successful
            // Decrypt and process Alice's message
            //unsigned char decryptedMessage[KEY_SIZE];
           // decryptFunction(bobSecretKey, aliceCiphertext, sizeof(aliceCiphertext), decryptedMessage);
            // Process the decrypted message
       // } else {
       // printf("ff");
            // Signature verification failed, handle accordingly
       // }

        // Encrypt and sign Bob's message
       // unsigned char bobMessage[] = "Hello Alice!";
       // unsigned char bobCiphertext[KEY_SIZE];
       // unsigned char bobSignature[KEY_SIZE];
       // encryptAndSign(bobSecretKey, bobPublicKey, bobMessage, sizeof(bobMessage), bobCiphertext, bobSignature);

        // Send Bob's encrypted message and signature to Alice
        // Alice receives Bob's message and verifies the signature
        //if (verifySignature(alicePublicKey, bobMessage, sizeof(bobMessage), bobSignature)) {
            // Signature verification successful
            // Decrypt and process Bob's message
           // unsigned char decryptedMessage[KEY_SIZE];
           // decryptFunction(aliceSecretKey, bobCiphertext, sizeof(bobCiphertext), decryptedMessage);
            // Process the decrypted message
       // } else {
            // Signature verification failed, handle accordingly
       // }
        
        
        
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

