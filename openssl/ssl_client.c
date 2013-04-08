#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>

static int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    /* For the purposes of this demonstration, the password is "ibmdw" */

    printf("*** Callback function called\n");
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

int main(int argc, char *argv[])
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
    int (*callback)(char *, int, int, void *) = &password_callback;

	SSL_library_init();

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();

    printf("Attempting to create SSL context...\n");
    ctx = SSL_CTX_new(SSLv3_client_method());
    if(ctx == NULL) {
        printf("Failed. Aborting.\n");
        ERR_print_errors_fp(stdout);
        return 0;
    }

    printf("\nLoading certificates...\n");
    SSL_CTX_set_default_passwd_cb(ctx, callback);
	if (!SSL_CTX_load_verify_locations(ctx, "./CAtest/cacert.pem", NULL)) {
		/* Handle failed load here */
        ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (SSL_CTX_use_certificate_file(ctx, "./CAtest/client_cert.pem", SSL_FILETYPE_PEM) != 1) {
	//if (SSL_CTX_use_certificate_chain_file(ctx, "./CA/client_cert.pem") != 1) {
		/* Handle failed load here */
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, "./CAtest/private/client_key.pem", SSL_FILETYPE_PEM) != 1) {
		/* Handle failed load here */
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
	SSL_CTX_set_verify_depth(ctx, 5);

    //SSL_CTX_set_default_passwd_cb(ctx, callback);
    printf("Attempting to create BIO object...\n");
    bio = BIO_new_ssl_connect(ctx);
    if(bio == NULL) {
        printf("Failed. Aborting.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }

    printf("\nAttempting to set up BIO for SSL...\n");
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

	BIO_set_conn_hostname(bio, "127.0.0.1:4422");
	if (BIO_do_connect(bio) <= 0) {
        printf("BIO_do_connect failed\n");
		/* Handle failed connection */
        ERR_print_errors_fp(stdout);
		exit (1);
	}
	if(SSL_get_verify_result(ssl) != X509_V_OK) {
        printf("SSL_get_verify_result failed\n");
		/* Handle the failed verification */
        ERR_print_errors_fp(stdout);
		//exit (1);
	}

	SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
	if (cipher) {
		char buf[1204];
		printf("Cipher Name: %s\n", SSL_CIPHER_get_name(cipher));
		printf("Cipher Desc: %s\n", SSL_CIPHER_description(cipher, buf, 1024));
	}

	int len = 1024;
	char buf[len];
	BIO_puts(bio, "Hello Server, this is just for test!");
	BIO_flush(bio);
	BIO_read(bio, buf, len);
	printf("Received: %s\n", buf);

	SSL_CTX_free(ctx);
	/* To reuse the connection, use this line */
	BIO_reset(bio);
	/* To free it from memory, use this line */
	BIO_free_all(bio);

	return 0;
}
