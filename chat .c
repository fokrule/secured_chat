#include <gtk/gtk.h>
#include <glib/gunicode.h> /* for utf8 strlen */
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/hmac.h>
#include <getopt.h>
#include "dh.h"
#include "keys.h"
#include "handshake.h"
#include <openssl/bn.h>
#include <openssl/rand.h>

//git commit

#include <stdio.h>
#include <gmp.h>
#include <string.h>
#include <stdlib.h>


// for generating key
#include <openssl/pem.h>
#include <assert.h>
#include <openssl/x509.h>
#define KEY_LENGTH 2048

#ifndef PATH_MAX
#define PATH_MAX 1024
#endif

static GtkTextBuffer* tbuf; /* transcript buffer */
static GtkTextBuffer* mbuf; /* message buffer */
static GtkTextView*  tview; /* view for transcript */
static GtkTextMark*   mark; /* used for scrolling to end of transcript, etc */

// Structure to hold public and private keys
typedef struct {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *g;
    BIGNUM *x; // private key
    BIGNUM *y; // public key
} SchnorrKeyPair;


// Function to generate a random secret key for HMAC
void generateHMACKey(unsigned char* key, size_t key_length) {
    if (RAND_bytes(key, key_length) != 1) {
        perror("Error generating random key for HMAC");
        exit(EXIT_FAILURE);
    }
}


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

static pthread_t trecv;     /* wait for incoming messagess and post to queue */
void* recvMsg(void*);       /* for trecv */

#define max(a, b)         \
	({ typeof(a) _a = a;    \
	 typeof(b) _b = b;    \
	 _a > _b ? _a : _b; })

/* network stuff... */

static int listensock, sockfd;
static int isclient = 1;



/* rsa encryption function start*/
RSA *alice_private_key, *alice_public_key;
RSA *bob_private_key, *bob_public_key;
void generate_key_pair(RSA **private_key, RSA **public_key) {
    *private_key = RSA_generate_key(KEY_LENGTH, RSA_F4, NULL, NULL);
    *public_key = RSAPublicKey_dup(*private_key);
}

void encrypt_message(const char *message, const RSA *public_key, unsigned char **encrypted_message, size_t *encrypted_len) {
    *encrypted_message = (unsigned char *)malloc(RSA_size(public_key));
    *encrypted_len = RSA_public_encrypt(strlen(message) + 1, (const unsigned char *)message, *encrypted_message, public_key, RSA_PKCS1_OAEP_PADDING);
}

void decrypt_message(const unsigned char *encrypted_message, size_t encrypted_len, const RSA *private_key, char **decrypted_message) {
printf("Encrypted Message: %s\n", encrypted_message);  // Assuming it's a string
    printf("Encrypted Length: %zu\n", encrypted_len);
    printf("Decrypted Message within the function1: %s\n", *decrypted_message); 
    printf("Decrypted Message within the private_key: %s\n", private_key); 
    *decrypted_message = (char *)malloc(RSA_size(private_key));
    RSA_private_decrypt(encrypted_len, encrypted_message, (unsigned char *)*decrypted_message, private_key, RSA_PKCS1_OAEP_PADDING);
    
    printf("Decrypted Message within the function: %s\n", *decrypted_message); 
}


// rsa enc funtion end  




static void error(const char *msg)
{
	perror(msg);
	exit(EXIT_FAILURE);
}

int generateKeyPair(struct dhKey* k) {
    assert(k);
    EVP_PKEY* pkey;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);

    if (ctx == NULL || EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        perror("Error generating key pair");
        return -1;
    }

    // Convert the generated key to strings
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL);
//    BIO_get_mem_data(bio, &k->SK, NULL); replaced to run on my ssl version
    BIO_ctrl(bio, BIO_CTRL_INFO, 0, (char*)&k->SK);

    BIO_free_all(bio);

    bio = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(bio, pkey);
    //BIO_get_mem_data(bio, &k->PK, NULL); replaced to run on my ssl version
    BIO_ctrl(bio, BIO_CTRL_INFO, 0, (char*)&k->SK);
    BIO_free_all(bio);

    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(ctx);

    return 0;
}

int initServerNet(int port)
{
	int reuse = 1;
	struct sockaddr_in serv_addr;
	listensock = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
	/* NOTE: might not need the above if you make sure the client closes first */
	if (listensock < 0)
		error("ERROR opening socket");
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = INADDR_ANY;
	serv_addr.sin_port = htons(port);
	if (bind(listensock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
		error("ERROR on binding");
	fprintf(stderr, "listening on port %i...\n",port);
	listen(listensock,1);
	socklen_t clilen;
	struct sockaddr_in  cli_addr;
	sockfd = accept(listensock, (struct sockaddr *) &cli_addr, &clilen);
	if (sockfd < 0)
		error("error on accept");
	close(listensock);
	fprintf(stderr, "connection made, starting session...\n");
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int initClientNet(char* hostname, int port)
{
	struct sockaddr_in serv_addr;
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	struct hostent *server;
	if (sockfd < 0)
		error("ERROR opening socket");
	server = gethostbyname(hostname);
	//server = gethostbyname("10.0.2.15");
	if (server == NULL) {
		fprintf(stderr,"ERROR, no such host\n");
		exit(0);
	}
	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	memcpy(&serv_addr.sin_addr.s_addr,server->h_addr,server->h_length);
	serv_addr.sin_port = htons(port);
	if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0){
		fprintf(stderr, "Attempting to connect to %s:%d\n", hostname, port);
		error("ERROR connecting to the server");
	}
	/* at this point, should be able to send/recv on sockfd */
	return 0;
}

static int shutdownNetwork()
{
	shutdown(sockfd,2);
	unsigned char dummy[64];
	ssize_t r;
	do {
		r = recv(sockfd,dummy,64,0);
	} while (r != 0 && r != -1);
	close(sockfd);
	return 0;
}

/* end network stuff. */


static const char* usage =
"Usage: %s [OPTIONS]...\n"
"Secure chat (CCNY computer security project).\n\n"
"   -c, --connect HOST  Attempt a connection to HOST.\n"
"   -l, --listen        Listen for new connections.\n"
"   -p, --port    PORT  Listen or connect on PORT (defaults to 1337).\n"
"   -h, --help          show this message and exit.\n";

/* Append message to transcript with optional styling.  NOTE: tagnames, if not
 * NULL, must have it's last pointer be NULL to denote its end.  We also require
 * that messsage is a NULL terminated string.  If ensurenewline is non-zero, then
 * a newline may be added at the end of the string (possibly overwriting the \0
 * char!) and the view will be scrolled to ensure the added line is visible.  */
static void tsappend(char* message, char** tagnames, int ensurenewline)
{
	GtkTextIter t0;
	gtk_text_buffer_get_end_iter(tbuf,&t0);
	size_t len = g_utf8_strlen(message,-1);
	if (ensurenewline && message[len-1] != '\n')
		message[len++] = '\n';
	gtk_text_buffer_insert(tbuf,&t0,message,len);
	GtkTextIter t1;
	gtk_text_buffer_get_end_iter(tbuf,&t1);
	/* Insertion of text may have invalidated t0, so recompute: */
	t0 = t1;
	gtk_text_iter_backward_chars(&t0,len);
	if (tagnames) {
		char** tag = tagnames;
		while (*tag) {
			gtk_text_buffer_apply_tag_by_name(tbuf,*tag,&t0,&t1);
			tag++;
		}
	}
	if (!ensurenewline) return;
	gtk_text_buffer_add_mark(tbuf,mark,&t1);
	gtk_text_view_scroll_to_mark(tview,mark,0.0,0,0.0,0.0);
	gtk_text_buffer_delete_mark(tbuf,mark);
}

static void sendMessage(GtkWidget* w /* <-- msg entry widget */, gpointer /* data */)
{
	

    generate_key_pair(&alice_private_key, &alice_public_key);
    generate_key_pair(&bob_private_key, &bob_public_key);
    	

	// Generate Schnorr proof
    SchnorrProof *deniableProof = generateSchnorrProof(deniableKeyPair, challenge);

    // Send the Schnorr proof along with the message
    ssize_t proofBytes = send(sockfd, deniableProof, sizeof(SchnorrProof), 0);
    if (proofBytes == -1) {
        error("send proof failed");
    }
    	
<<<<<<< HEAD:chat.c
    	printf("alice_encrypted_message bobbbbb: %s\n", bob_private_key);
=======
    	
    // Generate a random secret key for HMAC
    unsigned char hmac_key[EVP_MAX_KEY_LENGTH];
    generateHMACKey(hmac_key, EVP_MAX_KEY_LENGTH);

  	  // Calculate HMAC of the message
    unsigned char* message = gtk_text_buffer_get_text(mbuf, &mstart, &mend, 1);
    size_t message_len = g_utf8_strlen(message, -1);
    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    calculateHMAC(hmac_key, EVP_MAX_KEY_LENGTH, (const unsigned char*)message, message_len, hmac_result);

    // Send the HMAC along with the message
    ssize_t nbytes;
    if ((nbytes = send(sockfd, hmac_result, EVP_MAX_MD_SIZE, 0)) == -1)
        error("send failed");
>>>>>>> origin:chat .c
    	
	char* tags[2] = {"self",NULL};
	tsappend("me: ",tags,0);
	GtkTextIter mstart; /* start of message pointer */
	GtkTextIter mend;   /* end of message pointer */
	gtk_text_buffer_get_start_iter(mbuf,&mstart);
	gtk_text_buffer_get_end_iter(mbuf,&mend);
	char* message = gtk_text_buffer_get_text(mbuf,&mstart,&mend,1);
	size_t len = g_utf8_strlen(message,-1);
	/* XXX we should probably do the actual network stuff in a different
	 * thread and have it call this once the message is actually sent. */
	 
	 const char *alice_message = message;
    unsigned char *alice_encrypted_message;
    size_t alice_encrypted_len;
    encrypt_message(alice_message, bob_public_key, &alice_encrypted_message, &alice_encrypted_len);
    
	 //printf("alice_message length: %zu\n", strlen(alice_message));
	//printf("alice_encrypted_message length: %zu\n", alice_encrypted_len);
	printf("alice_encrypted_message content: %s\n", alice_encrypted_message);
	//char* base64EncodedMessage = base64_encode(alice_encrypted_message, alice_encrypted_len);
	
//	printf("base64EncodedMessage: %s\n", base64EncodedMessage);

	//ssize_t nbytes;
	//if ((nbytes = send(sockfd,alice_encrypted_message,alice_encrypted_len,0)) == -1)
	//	error("send failed");


	// sending all the encrypted messages.
	 int remaining_bytes = alice_encrypted_len;
  int sent_bytes = 0;

  while (remaining_bytes > 0) {
    int nbytes = send(sockfd, alice_encrypted_message + sent_bytes, remaining_bytes, 0);
    if (nbytes == -1) {
      error("send failed");
      break;
    }

    sent_bytes += nbytes;
    remaining_bytes -= nbytes;
  }

	// Clean up
    freeSchnorrProof(deniableProof);

	tsappend(message,NULL,1);
	free(message);
	/* clear message text and reset focus */
	gtk_text_buffer_delete(mbuf,&mstart,&mend);
	gtk_widget_grab_focus(w);


}

static gboolean shownewmessage(gpointer msg)
{
	char* tags[2] = {"friend",NULL};
	char* friendname = "mr. friend: ";
	tsappend(friendname,tags,0);
	char* message = (char*)msg;
	tsappend(message,NULL,1);
	free(message);
	return 0;
}

int main(int argc, char *argv[])
{
	if (init("params") != 0) {
		fprintf(stderr, "could not read DH params from file 'params'\n");
		return 1;
	}
	
	if (initParamsFromFile("params", q, p, g) != 0) {
	    fprintf(stderr, "could not read DH params from file 'params'\n");
	    return 1;
	}

	SchnorrKeyPair *deniableKeyPair = generateSchnorrKeyPair();
	// Perform Handshake
    	handshakeProtocol();
	//if (isclient) {
	    //initClientNet(hostname, port);
	    //struct dhKey myKey;
	    //initKey(&myKey);
	    //generateKeyPair(&myKey);
	    //performHandshakeClient(&myKey);  // Pass myKey to the handshake function
	//} else {
	   // initServerNet(port);
	   // struct dhKey myKey;
	   // initKey(&myKey);
	   // generateKeyPair(&myKey);
	   // performHandshakeServer(&myKey);  // Pass myKey to the handshake function
	//}
	// define long options
	static struct option long_opts[] = {
		{"connect",  required_argument, 0, 'c'},
		{"listen",   no_argument,       0, 'l'},
		{"port",     required_argument, 0, 'p'},
		{"help",     no_argument,       0, 'h'},
		{0,0,0,0}

	// Clean up
    freeSchnorrKeyPair(deniableKeyPair);

    
	};
	// process options:
	char c;
	int opt_index = 0;
	int port = 631;
	char hostname[HOST_NAME_MAX+1] = "127.0.0.1";
	hostname[HOST_NAME_MAX] = 0;

	while ((c = getopt_long(argc, argv, "c:lp:h", long_opts, &opt_index)) != -1) {
		switch (c) {
			case 'c':
				if (strnlen(optarg,HOST_NAME_MAX))
					strncpy(hostname,optarg,HOST_NAME_MAX);
				break;
			case 'l':
				isclient = 0;
				break;
			case 'p':
				port = atoi(optarg);
				break;
			case 'h':
				printf(usage,argv[0]);
				return 0;
			case '?':
				printf(usage,argv[0]);
				return 1;
		}
	}
	/* NOTE: might want to start this after gtk is initialized so you can
	 * show the messages in the main window instead of stderr/stdout.  If
	 * you decide to give that a try, this might be of use:
	 * https://docs.gtk.org/gtk4/func.is_initialized.html */
	if (isclient) {
		initClientNet(hostname,port);
	} else {
		initServerNet(port);
	}

	/* setup GTK... */
	GtkBuilder* builder;
	GObject* window;
	GObject* button;
	GObject* transcript;
	GObject* message;
	GError* error = NULL;
	gtk_init(&argc, &argv);
	builder = gtk_builder_new();
	if (gtk_builder_add_from_file(builder,"layout.ui",&error) == 0) {
		g_printerr("Error reading %s\n", error->message);
		g_clear_error(&error);
		return 1;
	}
	mark  = gtk_text_mark_new(NULL,TRUE);
	window = gtk_builder_get_object(builder,"window");
	g_signal_connect(window, "destroy", G_CALLBACK(gtk_main_quit), NULL);
	transcript = gtk_builder_get_object(builder, "transcript");
	tview = GTK_TEXT_VIEW(transcript);
	message = gtk_builder_get_object(builder, "message");
	tbuf = gtk_text_view_get_buffer(tview);
	mbuf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(message));
	button = gtk_builder_get_object(builder, "send");
	g_signal_connect_swapped(button, "clicked", G_CALLBACK(sendMessage), GTK_WIDGET(message));
	gtk_widget_grab_focus(GTK_WIDGET(message));
	GtkCssProvider* css = gtk_css_provider_new();
	gtk_css_provider_load_from_path(css,"colors.css",NULL);
	gtk_style_context_add_provider_for_screen(gdk_screen_get_default(),
			GTK_STYLE_PROVIDER(css),
			GTK_STYLE_PROVIDER_PRIORITY_USER);

	/* setup styling tags for transcript text buffer */
	gtk_text_buffer_create_tag(tbuf,"status","foreground","#657b83","font","italic",NULL);
	gtk_text_buffer_create_tag(tbuf,"friend","foreground","#6c71c4","font","bold",NULL);
	gtk_text_buffer_create_tag(tbuf,"self","foreground","#268bd2","font","bold",NULL);

	/* start receiver thread: */
	if (pthread_create(&trecv,0,recvMsg,0)) {
		fprintf(stderr, "Failed to create update thread.\n");
	}


	gtk_main();

	shutdownNetwork();
	return 0;
}

gboolean is_valid_utf8(const char *text, gsize len) {
  return g_utf8_validate(text, len, NULL);
}

/* thread function to listen for new messages and post them to the gtk
 * main loop for processing: */
void* recvMsg(void*)
{	


	size_t maxlen = sizeof(SchnorrProof);
    SchnorrProof deniableProof;


	size_t maxlen = 512;
	char msg[maxlen+2]; /* might add \n and \0 */
	ssize_t nbytes;
	while (1) {
		
		if ((nbytes = recv(sockfd,msg,maxlen,0)) == -1)
			error("recv failed");
		if (nbytes == 0) {
			/* XXX maybe show in a status message that the other
			 * side has disconnected. */
			return 0;
		}
		char* m = malloc(maxlen+2);
		memcpy(m,msg,nbytes);
		if (m[nbytes-1] != '\n')
			m[nbytes++] = '\n';
		m[nbytes] = 0;
		printf("base64EncodedMessage dec: %s\n", msg);
		/*size_t decodedLength;
    		unsigned char* alicedecodedMessage = base64_decode(m, nbytes, &decodedLength);
    		printf("alice_encrypted_message content: %s\n", alicedecodedMessage);
    		char *bob_decrypted_message;
    		size_t alicedecodedMessageLen = strlen(alicedecodedMessage);

    		decrypt_message(alicedecodedMessage, 256, bob_private_key, &bob_decrypted_message);
    		printf("Bob received and decrypted: '%s'\n", bob_decrypted_message);*/
    		/*gboolean text_is_valid_utf8 = is_valid_utf8(bob_decrypted_message, strlen(bob_decrypted_message));
		if (text_is_valid_utf8) {
		  g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
		} else {
		  // Handle invalid UTF-8 text
		}*/
		//char *bob_decrypted_message;
    		//decrypt_message(msg, 256, bob_private_key, &bob_decrypted_message);
    		//printf("Bob received and decrypted: '%s'\n", &bob_decrypted_message);

		//g_main_context_invoke(NULL,shownewmessage,(gpointer)m);
	}
	return 0;


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
        }

        

        // Clean up
        freeSchnorrProof(&deniableProof);

       
    }

}
