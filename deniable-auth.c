#include <openssl/bn.h>

// Structure to hold public and private keys
typedef struct {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *x; // private key
    BIGNUM *y; // public key
} SchnorrKeyPair;

// Schnorr protocol parameters
typedef struct {
    BIGNUM *r;
    BIGNUM *c;
} SchnorrProof;

SchnorrKeyPair* generateSchnorrKeyPair() {
    // Implementation of key pair generation
}

SchnorrProof* generateSchnorrProof(const SchnorrKeyPair *keyPair, const BIGNUM *challenge) {
    // Implementation of proof generation
}

int verifySchnorrProof(const SchnorrKeyPair *keyPair, const BIGNUM *challenge, const SchnorrProof *proof) {
    // Implementation of proof verification
}

int main(int argc, char *argv[]) {
    // ...

    SchnorrKeyPair *deniableKeyPair = generateSchnorrKeyPair();

    // ...

    // Clean up
    freeSchnorrKeyPair(deniableKeyPair);

    // ...
}

static void sendMessage(GtkWidget* w, gpointer data) {
    // ...

    // Generate Schnorr proof
    SchnorrProof *deniableProof = generateSchnorrProof(deniableKeyPair, challenge);

    // Send the Schnorr proof along with the message
    ssize_t proofBytes = send(sockfd, deniableProof, sizeof(SchnorrProof), 0);
    if (proofBytes == -1) {
        error("send proof failed");
    }

    // ...

    // Clean up
    freeSchnorrProof(deniableProof);

    // ...
}

void* recvMsg(void*) {
    size_t maxlen = sizeof(SchnorrProof);
    SchnorrProof deniableProof;

    // ...

    while (1) {
        // Receive the Schnorr proof
        ssize_t proofBytes = recv(sockfd, &deniableProof, maxlen, 0);
        if (proofBytes == -1) {
            error("recv proof failed");
        }

        // Verify the Schnorr proof
        int verificationResult = verifySchnorrProof(deniableKeyPair, challenge, &deniableProof);
        if (!verificationResult) {
            fprintf(stderr, "Deniable authentication failed.\n");
            // Handle authentication failure as needed
        }

        // ...

        // Clean up
        freeSchnorrProof(&deniableProof);

        // ...
    }
}
