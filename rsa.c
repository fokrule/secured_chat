#include <openssl/evp.h>

int main() {
  // Generate a new RSA key pair
  EVP_PKEY *pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    // Handle error
  }

  EVP_PKEY_set_type(pkey, EVP_PKEY_RSA);
  RSA *rsa = EVP_PKEY_get0_RSA(pkey);
  if (rsa == NULL) {
    // Handle error
  }

  // Get the public key
  unsigned char *public_key = NULL;
  size_t public_key_len = 0;
  if (EVP_PKEY_get_public_key_bytes(pkey, &public_key, &public_key_len) != 1) {
    // Handle error
  }

  // Get the private key
  unsigned char *private_key = NULL;
  size_t private_key_len = 0;
  if (EVP_PKEY_get_private_key_bytes(pkey, &private_key, &private_key_len) != 1) {
    // Handle error
  }

  // Encrypt a message
  char *message = "This is the message to encrypt";
  size_t message_len = strlen(message);
  unsigned char *encrypted_message = NULL;
  size_t encrypted_message_len = 0;

  EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new();
  if (ctx == NULL) {
    // Handle error
  }

  EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);

  if (EVP_PKEY_encrypt_init(ctx, pkey) != 1) {
    // Handle error
  }

  if (EVP_PKEY_encrypt(ctx, encrypted_message, &encrypted_message_len, (unsigned char *)message, message_len) <= 0) {
    // Handle error
  }
  EVP_PKEY_CTX_free(ctx);

  // Decrypt the message
  unsigned char *decrypted_message = NULL;
  size_t decrypted_message_len = 0;

  EVP_PKEY_CTX *dec_ctx = EVP_PKEY_CTX_new();
  if (dec_ctx == NULL) {
    // Handle error
  }

  EVP_PKEY_CTX_set_rsa_padding(dec_ctx, RSA_PKCS1_PADDING);

  if (EVP_PKEY_decrypt_init(dec_ctx, pkey) != 1) {
    // Handle error
  }

  if (EVP_PKEY_decrypt(dec_ctx, decrypted_message, &decrypted_message_len, encrypted_message, encrypted_message_len) <= 0) {
    // Handle error
  }
  EVP_PKEY_CTX_free(dec_ctx);

  // Print the decrypted message
  printf("Decrypted message: %s\n", decrypted_message);

  // Free the allocated memory
  OPENSSL_free(public_key);
  OPENSSL_free(private_key);
  OPENSSL_free(encrypted_message);
  OPENSSL_free(decrypted_message);
  RSA_free(rsa);
  EVP_PKEY_free(pkey);

  return 0;
}
