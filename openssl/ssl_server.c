#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#include <pthread.h>

static int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    /* For the purposes of this demonstration, the password is "ibmdw" */

    printf("*** Password callback function called\n");
    strcpy(buf, "password");
    return 1;
}

static int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
{
	printf("*** Verify callback function called\n");
	char    buf[256];
	X509   *err_cert;
	int     err, depth;
	SSL    *ssl;

	err_cert = X509_STORE_CTX_get_current_cert(ctx);
	err = X509_STORE_CTX_get_error(ctx);
	depth = X509_STORE_CTX_get_error_depth(ctx);

	/*
	 * Retrieve the pointer to the SSL of the connection currently treated
	 * and the application specific data stored into the SSL object.
	 */
	ssl = X509_STORE_CTX_get_ex_data(ctx, SSL_get_ex_data_X509_STORE_CTX_idx());
	//mydata = SSL_get_ex_data(ssl, mydata_index);

	X509_NAME_oneline(X509_get_subject_name(err_cert), buf, 256);

	/*
	 * Catch a too long certificate chain. The depth limit set using
	 * SSL_CTX_set_verify_depth() is by purpose set to "limit+1" so
	 * that whenever the "depth>verify_depth" condition is met, we
	 * have violated the limit and want to log this error condition.
	 * We must do it here, because the CHAIN_TOO_LONG error would not
	 * be found explicitly; only errors introduced by cutting off the
	 * additional certificates would be logged.
	 */
#if 0
	if (depth > mydata->verify_depth) {
		preverify_ok = 0;
		err = X509_V_ERR_CERT_CHAIN_TOO_LONG;
		X509_STORE_CTX_set_error(ctx, err);
	}
#endif
	if (!preverify_ok) {
		printf("verify error:num=%d:%s:depth=%d:%s\n", err,
				X509_verify_cert_error_string(err), depth, buf);
	}

	printf("depth=%d:%s\n", depth, buf);

	/*
	 * At this point, err contains the last verification error. We can use
	 * it for something special
	 */
	if (!preverify_ok && (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT)) {
		X509_NAME_oneline(X509_get_issuer_name(ctx->current_cert), buf, 256);
		printf("issuer= %s\n", buf);
	}

#if 0
	if (mydata->always_continue)
		return 1;
	else
#endif
		return preverify_ok;

}

void *handle_connection(void *arg)
{
	char buf[1024];
	BIO *bio = (BIO *)arg;
	X509 *peer;
	SSL *ssl;

	BIO_get_ssl(bio, &ssl);

	if (BIO_do_handshake(bio) <= 0) {
		printf("Failed handshake.\n");
		ERR_print_errors_fp(stdout);
		return (void *)-1;
	}

	if ((peer = SSL_get_peer_certificate(ssl))) {
		if (SSL_get_verify_result(ssl) == X509_V_OK) {
			/* The client sent a certificate which verified OK */
			printf("The client sent a certificate which verified OK\n");
		} else {
			printf("The client sent a certificate which verified failed\n");
		}
	} else {
		fprintf(stderr, "cannot get peer certificate\n");
	}

	BIO_read(bio, buf, 1024);
	printf("Received: %s\n", buf);
	BIO_puts(bio, "Connection: Sending out Data on initial connection\n");
	printf("Sent out data on connection\n");

	BIO_free_all(bio);

	return (void *)0;
}

int main(int argc, char *argv[])
{
	SSL *ssl;
	SSL_CTX *ctx;
	BIO *bio, *abio, *cbio;
	pthread_t t;
	X509 *peer;
	int (*callback)(char *, int, int, void *) = &password_callback;

	SSL_library_init();

	SSL_load_error_strings();
	ERR_load_BIO_strings();
	ERR_load_SSL_strings();

	printf("Attempting to create SSL context...\n");
	ctx = SSL_CTX_new(SSLv3_server_method());
	if(ctx == NULL) {
		printf("Failed. Aborting.\n");
		ERR_print_errors_fp(stdout);
		return 0;
	}

	printf("Loading certificates...\n");
	SSL_CTX_set_default_passwd_cb(ctx, callback);
	//if (SSL_CTX_use_certificate_file(ctx, "./CA/server_cert.pem", SSL_FILETYPE_PEM) != 1) {
	if (SSL_CTX_use_certificate_chain_file(ctx, "./CAtest/server_cert.pem") != 1) {
		/* Handle failed load here */
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./CAtest/private/server_key.pem", SSL_FILETYPE_PEM) != 1) {
		/* Handle failed load here */
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (!SSL_CTX_load_verify_locations(ctx, "./CAtest/cacert.pem", "./CA/")) {
		/* Handle failed load here */
        ERR_print_errors_fp(stdout);
		exit(1);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT | SSL_VERIFY_CLIENT_ONCE, verify_callback);
	SSL_CTX_set_verify_depth(ctx, 5);

	printf("Attempting to create BIO object...\n");
	bio = BIO_new_ssl(ctx, 0);
	if(bio == NULL) {
		printf("Failed. Aborting.\n");
		ERR_print_errors_fp(stdout);
		SSL_CTX_free(ctx);
		return 0;
	}

	printf("Attempting to set up BIO for SSL...\n");
	BIO_get_ssl(bio, &ssl);
	SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	abio = BIO_new_accept("4422");
	BIO_set_accept_bios(abio, bio);

	/* First call to BIO_accept() sets up accept BIO */
	if (BIO_do_accept(abio) <= 0) {
		fprintf(stderr, "Error setting up accept\n");
		ERR_print_errors_fp(stderr);
		exit(0);
	}

	do {
		/* Wait for incoming connection */
		if (BIO_do_accept(abio) <= 0) {
			fprintf(stderr, "Error accepting connection\n");
			ERR_print_errors_fp(stderr);
			exit(0);
		}

		fprintf(stderr, "Connection 1 established\n");
		/* Retrieve BIO for connection */
		cbio = BIO_pop(abio);
		pthread_create(&t, NULL, handle_connection, cbio);
	} while (1);

	SSL_shutdown(ssl);
	BIO_free_all(bio);
	BIO_free_all(abio);
	SSL_CTX_free(ctx);
	SSL_free(ssl);

	return 0;
}
