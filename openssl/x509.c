#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

#include <bio.h>
#include <bn.h>
#include <ssl.h>

int main(int argc, char *argv[])
{
	/*
	BIGNUM *a,*b,*c;
	BIO *out;

	a=BN_new();
	out=BIO_new (BIO_s_file()) ;
	BIO_set_fp(out,stdout,BIO_CLOSE);

	BN_rand(a,128,0,0);
	BN_print(out, a);
	BIO_puts(out,"\n");
	*/
	BIO *in;
	X509 *x509;
	X509_REQ *req;
	X509_EXTENSION *ext, *tmpext;
	STACK_OF(X509_EXTENSION) *exts = NULL;
	ASN1_OBJECT *obj;
	int i, idx, ret = 0;
	char *buf;
	int len = 8192, read_bytes;

	if (argc < 2) {
		fprintf(stderr, "usage: %s <file name>\n", argv[0]);
		return 1;
	}

	int fd = open(argv[1], O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "cannot open file: %s\n", argv[1]);
		return 1;
	}

	in = BIO_new_fd(fd, BIO_NOCLOSE);
	if (!in) {
		return 2;
	}

	x509 = d2i_X509_bio(in, NULL);

	//buf = OPENSSL_malloc(8192);
	//read_bytes = BIO_read(in, buf, len);
	//
	exts = x509->cert_info->extensions;
	char *value = OPENSSL_malloc(128);
	for(i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
	ext = sk_X509_EXTENSION_value(exts, i);
		obj = X509_EXTENSION_get_object(ext);
		//idx = X509_get_ext_by_OBJ(x, obj, -1);
		OBJ_obj2txt(value, 128, obj, 0);
		printf("extension: %s\n", value);
		
		ASN1_OCTET_STRING *data= X509_EXTENSION_get_data(ext);
		const unsigned char* octet_str_data = data->data;
		long xlen;
		int tag, xclass;
		int ret = ASN1_get_object(&octet_str_data, &xlen, &tag, &xclass, data->length);
		printf("tag: %d value: %s\n", tag, data->data);
	}
	OPENSSL_free(value);

	/*
	req = d2i_X509_REQ_bio(in, &req);

	exts = X509_REQ_get_extensions(req);

	char *value = OPENSSL_malloc(128);
	for(i = 0; i < sk_X509_EXTENSION_num(exts); i++) {
	ext = sk_X509_EXTENSION_value(exts, i);
		obj = X509_EXTENSION_get_object(ext);
		//idx = X509_get_ext_by_OBJ(x, obj, -1);
		OBJ_obj2txt(value, 128, obj, 0);
		printf("extension: %s", value);
	}
	OPENSSL_free(value);
	*/
	close(fd);

	return 0;
}
