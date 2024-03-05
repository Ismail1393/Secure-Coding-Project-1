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
