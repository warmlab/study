#include "stdio.h"
#include "string.h"

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

int password_callback(char *buf, int size, int rwflag, void *userdata)
{
    /* For the purposes of this demonstration, the password is "ibmdw" */

    printf("*** Callback function called\n");
    strcpy(buf, "ibmdw");
    return 1;
}

int main()
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio, *abio, *out, *sbio;

    int (*callback)(char *, int, int, void *) = &password_callback;

    printf("Secure Programming with the OpenSSL API, Part 4:\n");
    printf("Serving it up in a secure manner\n\n");

	SSL_library_init();

    SSL_load_error_strings();
    ERR_load_BIO_strings();
    ERR_load_SSL_strings();
    OpenSSL_add_all_algorithms();

    printf("Attempting to create SSL context...\n");
    ctx = SSL_CTX_new(SSLv23_server_method());
    if(ctx == NULL)
    {
        printf("Failed. Aborting.\n");
        ERR_print_errors_fp(stdout);
        return 0;
    }

    printf("\nLoading certificates...\n");
    SSL_CTX_set_default_passwd_cb(ctx, callback);
    if(!SSL_CTX_use_certificate_file(ctx, "certificate.pem", SSL_FILETYPE_PEM))
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }
    if(!SSL_CTX_use_PrivateKey_file(ctx, "private.key", SSL_FILETYPE_PEM))
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }

    printf("Attempting to create BIO object... ");
    bio = BIO_new_ssl(ctx, 0);
    if(bio == NULL)
    {
        printf("Failed. Aborting.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        return 0;
    }

    printf("\nAttempting to set up BIO for SSL...\n");
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
    
    abio = BIO_new_accept("4422");
    BIO_set_accept_bios(abio, bio);

    printf("Waiting for incoming connection...\n");

    if(BIO_do_accept(abio) <= 0)
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    if(BIO_do_accept(abio) <= 0)
    {
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    out = BIO_pop(abio);

    if(BIO_do_handshake(out) <= 0)
    {
        printf("Handshake failed.\n");
        ERR_print_errors_fp(stdout);
        SSL_CTX_free(ctx);
        BIO_free_all(bio);
        BIO_free_all(abio);
        return;
    }

    BIO_puts(out, "Hello\n");
    BIO_flush(out);

    BIO_free_all(out);
    BIO_free_all(bio);
    BIO_free_all(abio);

    SSL_CTX_free(ctx);
}
