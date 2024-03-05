# Secure-Coding-Project-1
## Implementation
I started the TLS client program implementation by seeking advice on how to write a C client program that complies with particular security specifications. The intended software had to send a "hello server" message and establish a connection to a server using the IP address and port number that were supplied. The listed security needs were:
1.	"SecureCoding Test TLS Server" must appear in the server's certificate common name.
2.	The only root CA included in the current directory is required to be the root CA of the server's certificate.
   
I was advised to use the OpenSSL library in C for this purpose. The key steps I took during the implementation process were:
To establish a secure connection using OpenSSL, the process typically involves several steps. First, the OpenSSL library is initialized to enable cryptographic functions. Next, an SSL context is created, which sets parameters for the SSL connection. Then, the client connects to the server and initiates an SSL handshake to establish secure communication. During this handshake, the server's certificate common name and chain are verified to ensure the authenticity of the server. Once the handshake is successful, the client sends a "hello server" message, and the server responds with a message. Finally, after the communication is complete, resources are cleaned up, and the connection is closed to release system resources. This process ensures secure and encrypted communication between the client and server.

I ran into a few problems with the implementation, such as missing log messages for each security criteria that wasn't met and syntax errors. I also encountered a problem where the server's certificate had expired, making the built-in certificate verification feature useless. As such, I was unable to depend on OpenSSL's default certificate verification mechanism. I asked ChatGPT for help in order to solve this problem by creating a custom function that ensured security standards were met and got around the issue of the expiring certificate. I was able to fix these problems and strengthen the implementation of the SSL connection with the help of the right code snippets that were supplied, as well as some tips for improving error reporting through log messages.

## Findings & Details
I tested the TLS client program with three different server instances, and here are the results:
1.	Server instance 1 (IP: 10.10.10.164, Port: 9000) 
 
This server instance did not meet the security requirement related to the root CA of the server's certificate. The client  code detected an issue in the verify certificate chain function. Line 70 in my code checks if the result obtained is correct and then gives an error in this case since the chain verification failed. And since that occurs then the program also gives an error about certificate validation failed which is on line 142.

![server output 1][/Picture1.png]

2.	Server instance 2 (IP: 10.10.10.164, Port: 9090)
 
This server instance met all the security requirements. The handshake was successful, and the client was able to send and receive messages.

3.	Server instance 3 (IP: 10.10.10.164, Port: 9999)
   
This server instance did not meet the security requirement related to the server's certificate common name. The client code detected this issue in the check common name function declared on line 25 and this returns an error which is mentioned in line 34. This function is called inside the certificate chain verification function in line 56.

## Help From ChatGPT
During the implementation phase, I was assisted and guided by OpenAI's ChatGPT AI language model. The AI gave explanations, code snippets, and step-by-step directions. I was able to effectively construct the TLS client program in C while adhering to the necessary security criteria thanks to the important questions I asked and the responses I received from the AI.

Prompt 1: "How do I initialize the OpenSSL library and create an SSL context for secure communication in C?"

Answer: To initialize the OpenSSL library, you should call the SSL_load_error_strings() and SSL_library_init() functions to load all error messages and algorithms, respectively. To create an SSL context, use the SSL_CTX_new() function with an appropriate method passed as an argument (for example, TLS_client_method() for a TLS client). Set any additional parameters you require on the context, such as setting the verification mode with SSL_CTX_set_verify().

Prompt 2: "How can I verify the server's certificate common name against a specific expected value in OpenSSL?"

Answer: After establishing the SSL connection, retrieve the server's certificate using SSL_get_peer_certificate() from the SSL object. Then, extract the common name from the certificate using X509_get_subject_name() and X509_NAME_get_text_by_NID(). Compare this common name with the expected value, and if they do not match, terminate the connection. Log the event if there is a mismatch.

Prompt 3: "How do I include and use only the specific root CA provided in the current directory for the server's certificate verification in OpenSSL?"

Answer: Use SSL_CTX_load_verify_locations() on your SSL context to specify the path of the CA certificate file. This function sets the location from which the CA's certificate can be loaded. Ensure no other CA certificates are in this directory or added to the context to maintain strict control over the trusted CAs.

Prompt 4: "How can I handle expired server certificates in OpenSSL while ensuring the connection remains secure?"

Answer: Implement a custom certificate verification callback using SSL_CTX_set_cert_verify_callback(). In the callback, manually verify the certificate's expiration date using X509_get_notBefore() and X509_get_notAfter(). Additionally, check other aspects of the certificate as needed. If the certificate is expired but other security criteria are met, decide based on your security policy whether to allow the connection. Log all decisions and relevant details.

## Screenshot
 


## How to Run the Code 
```
gcc finalcode.c -o final -lssl -lcrypto 
./final 10.10.10.164 9000 
./final 10.10.10.164 9090 
./final 10.10.10.164 9999
```
## Source Code
```
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define ROOT_CA_FILENAME "CA.root.crt.pem"
#define SERVER_CN "SecureCoding Test TLS Server"

void initialize_openssl() {
	SSL_library_init();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
}

void cleanup_openssl() {
	EVP_cleanup();
	ERR_free_strings();
}

int verify_cert_common_name(X509 *cert, const char *cn) {
	int result = 0;
	char subject_cn[256];
	
	X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, subject_cn, 			sizeof(subject_cn));
	if (strcmp(subject_cn, cn) == 0) {
		result = 1;
	} else {
		
		fprintf(stderr, "Error: Server certificate common name mismatch. Expected: %s, Actual: %s\n", cn, subject_cn);
	}
	return result;
}

int custom_verify_callback(int ok, X509_STORE_CTX *ctx) {
    // Ignore error related to certificate expiration
    int err = X509_STORE_CTX_get_error(ctx);
    if (err == X509_V_ERR_CERT_HAS_EXPIRED || err == X509_V_ERR_CERT_NOT_YET_VALID) {
        // Override the error
        X509_STORE_CTX_set_error(ctx, X509_V_OK);
        return 1; // Verification success
    }
    // For other errors, return the original status
    return ok;
}

int verify_cert_chain(SSL *ssl) {
	int result = 0;
	X509 *cert = SSL_get_peer_certificate(ssl);

	if (cert) {
		if (verify_cert_common_name(cert, SERVER_CN)) {
			STACK_OF(X509) *chain = sk_X509_new_null();
			if (chain) {
				sk_X509_push(chain, cert);
				X509_STORE *store = X509_STORE_new();
				if (store) {
					X509_STORE_CTX *ctx = X509_STORE_CTX_new();
					if (ctx) {
						X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
						if (lookup && X509_LOOKUP_load_file(lookup, ROOT_CA_FILENAME, X509_FILETYPE_PEM)){
							if (X509_STORE_CTX_init(ctx, store, cert, chain)) {	
								// Set the custom verification callback here
                                X509_STORE_CTX_set_verify_cb(ctx, custom_verify_callback);
								result = X509_verify_cert(ctx) > 0;
								if (!result) {
									fprintf(stderr, "Error: Certificate chain verification failed\n");
								}
								X509_STORE_CTX_cleanup(ctx);
							}
						} else {
							fprintf(stderr, "Error: Failed to load root CA from file: %s\n", ROOT_CA_FILENAME);
						}
						X509_STORE_CTX_free(ctx);
					}				
					X509_STORE_free(store);
				}
				sk_X509_free(chain);
			}
		}
		X509_free(cert);
	} else {
		fprintf(stderr, "Error: No server certificate found\n");
	}
	return result;
}




int main(int argc, char *argv[]) {

	if (argc != 3) {
		fprintf(stderr, "Usage: %s <server_ip> <server_port>\n", argv[0]);
		return 1;
	}

	initialize_openssl();

	SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());

	if (!ctx) {
		fprintf(stderr, "Unable to create SSL context\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}

	int server_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (server_fd < 0) {
		perror("Error creating socket");
		return 1;
	}

	struct sockaddr_in server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(atoi(argv[2]));
	inet_pton(AF_INET, argv[1], &server_addr.sin_addr);

	if (connect(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
		perror("Error connecting to server");
		return 1;
	}

	SSL *ssl = SSL_new(ctx);
	if (!ssl) {
		fprintf(stderr, "Unable to create SSL object\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	SSL_set_fd(ssl, server_fd);
	if (SSL_connect(ssl) <= 0) {
		fprintf(stderr, "Error establishing SSL connection\n");
		ERR_print_errors_fp(stderr);
		return 1;
	}
	if (!verify_cert_chain(ssl)) {
		fprintf(stderr, "Error: Certificate validation failed\n");
		return 1;
	}
	const char *msg = "hello server";
	int bytes_written = SSL_write(ssl, msg, strlen(msg));
	if (bytes_written <= 0) {
		fprintf(stderr, "Error sending message\n");
		ERR_print_errors_fp(stderr);
	} else {
		printf("Message sent: %s\n", msg);
		// Receive the message from the server
		char recv_buffer[1024];
		int bytes_received = SSL_read(ssl, recv_buffer, sizeof(recv_buffer) - 1);
	if (bytes_received <= 0) {
	fprintf(stderr, "Error receiving message\n");
	ERR_print_errors_fp(stderr);
	} else {
	recv_buffer[bytes_received] = '\0';
	printf("Message received: %s\n", recv_buffer);
	}
	}
	SSL_shutdown(ssl);
	SSL_free(ssl);
	close(server_fd);
	SSL_CTX_free(ctx);
	cleanup_openssl();
	return 0;
}
```
