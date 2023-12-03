// handshake.h
#pragma once
#include <gmp.h>
#ifndef HANDSHAKE_H
#define HANDSHAKE_H


#define KEY_SIZE 128

void encryptAndSign(mpz_t privateKey, mpz_t publicKey, unsigned char* message, size_t msgSize, unsigned char* ciphertext, unsigned char* signature);
int verifySignature(mpz_t publicKey, unsigned char* message, size_t msgSize, unsigned char* signature);
void deriveSharedSecretWithPublicKey(mpz_t ownSecretKey, mpz_t ownPublicKey, mpz_t otherPublicKey, unsigned char* sharedSecret, size_t keySize);
void generateMAC(unsigned char* key, unsigned char* message, size_t msgSize, unsigned char* mac);
int verifyMAC(unsigned char* key, unsigned char* message, size_t msgSize, unsigned char* mac);

void handshakeProtocol();

#endif  // HANDSHAKE_H

