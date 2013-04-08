#include <stdio.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#include <openssl/bio.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

EVP_PKEY* generate_PrivateKey()
{
	// Private key
	EVP_PKEY *pkey;
	// RSA key
	RSA *rsa;

	// Create private key
	pkey = EVP_PKEY_new();

	rsa = RSA_generate_key(2048, RSA_F4, NULL, NULL);
	if (!rsa) {
		printf("Error: %s\n", ERR_get_error());
		return NULL;
	}

	// Sign rsa key to pkey
	if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
		printf("Error: %s\n", ERR_get_error());
		return NULL;
	}

	// Finally
	//RSA_free(rsa);
	// It will free rsa when pkey is freed.
	//EVP_PKEY_free(pkey);
	//
	return pkey;
}

X509* generate_certificate(EVP_PKEY *pkey)
{
	X509 *x509;
	X509_NAME *name;
	STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ex;

	int len;
	unsigned char sha_hash[SHA_DIGEST_LENGTH];
	unsigned char name_hash[SHA_DIGEST_LENGTH];
	unsigned char pubkey_hash[SHA_DIGEST_LENGTH] = {0};

	x509 = X509_new();

	X509_set_version(x509, 2L);

	// adjust validation time
	X509_gmtime_adj(X509_get_notBefore(x509), 0); // current time
	X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // a year

	// set public key
	X509_set_pubkey(x509, pkey);

	// Since this is a self-signed certificate, we set the name of issuer to the name of the subject
	// Get subject name
	name = X509_get_subject_name(x509);
	X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_ASC, (unsigned char *)"CN", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_organizationName, MBSTRING_ASC, (unsigned char *)"Warmlab Inc.", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName, MBSTRING_ASC, (unsigned char *)"Dev", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName, MBSTRING_ASC, (unsigned char *)"Beijing", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_localityName, MBSTRING_ASC, (unsigned char*)"Beijing", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_pkcs9_emailAddress, MBSTRING_ASC, (unsigned char *)"root@warmlab.com", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char *)"Warmlab Root CA", -1, -1, 0);

	// Set issuer name
	X509_set_issuer_name(x509, name);

	// Set serial number
	if (X509_NAME_digest(name, EVP_sha1(), name_hash, &len) == 1) {
		if (X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len)) {
			for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
				sha_hash[i] = name_hash[i] ^ pubkey_hash[i];
			ASN1_INTEGER *serial_num = ASN1_INTEGER_new();
			if (serial_num) {
				ASN1_OCTET_STRING_set(serial_num, sha_hash, SHA_DIGEST_LENGTH);
				X509_set_serialNumber(x509, serial_num);
			} else {
				ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
			}
		} else {
			ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
		}
	} else {
		ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	}

	// Set basic constraints
	BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
	if (bc) {
		bc->ca = 1;
		//bc->pathlen = ASN1_INTEGER_new();
		//ASN1_INTEGER_set(bc->pathlen, 0);
		X509_add1_ext_i2d(x509, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT);

		BASIC_CONSTRAINTS_free(bc);
	} else {
		fprintf(stderr, "Cannot create BASIC_CONSTRAINTS\n");
	}

	// Set subject key identifier
	ASN1_OCTET_STRING *subjectKeyIdentifier = ASN1_OCTET_STRING_new();
	if (subjectKeyIdentifier) {
		if (!pubkey_hash[0]) {
			X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len);
		}
		ASN1_OCTET_STRING_set(subjectKeyIdentifier, pubkey_hash, SHA_DIGEST_LENGTH);
		X509_add1_ext_i2d(x509, NID_subject_key_identifier, subjectKeyIdentifier, 0, X509V3_ADD_DEFAULT);
		ASN1_OCTET_STRING_free(subjectKeyIdentifier);
	}

	// Set authority keyid
	AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
	if (akid) {
		akid->issuer = GENERAL_NAMES_new();
		GENERAL_NAME *gen_name = GENERAL_NAME_new();
		gen_name->type = GEN_DIRNAME;
		gen_name->d.directoryName = X509_NAME_dup(X509_get_subject_name(x509));
		sk_GENERAL_NAME_push(akid->issuer, gen_name);
		akid->keyid = (ASN1_OCTET_STRING*)X509_get_ext_d2i(x509, NID_subject_key_identifier, NULL, NULL);
		akid->serial = ASN1_INTEGER_dup(X509_get_serialNumber(x509));

		X509_add1_ext_i2d(x509, NID_authority_key_identifier, akid, 0, X509V3_ADD_DEFAULT);

		AUTHORITY_KEYID_free(akid);
	}

	// Set netscape comment
	ASN1_OCTET_STRING *comment = ASN1_OCTET_STRING_new();
	if (comment) {
		ASN1_OCTET_STRING_set(comment, (unsigned char *)"my comment just for test", 24);
		//ex = X509_EXTENSION_create_by_NID(&ex, NID_netscape_comment, 0, comment);
		//exts = X509v3_add_ext(NULL, ex, 0);
		X509_add1_ext_i2d(x509, NID_netscape_comment, comment, 0, X509V3_ADD_DEFAULT);
		ASN1_OCTET_STRING_free(comment);
	}

	// Finally sign certificate with pkey, SHA-1 hashing algorithm is used, and MD5 can be used.
	X509_sign(x509, pkey, EVP_sha1());

	// X509_free(x509);

	return x509;
}

X509_REQ *generate_request(EVP_PKEY *pkey, int ca)
{
	X509_REQ *req;
	X509_NAME *name;
	STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ex;
	int len;
	unsigned char sha_hash[SHA_DIGEST_LENGTH];
	unsigned char name_hash[SHA_DIGEST_LENGTH];
	unsigned char pubkey_hash[SHA_DIGEST_LENGTH] = {0};

	req = X509_REQ_new();

	X509_REQ_set_pubkey(req, pkey);

	name = X509_REQ_get_subject_name(req);
	X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_ASC, (unsigned char *)"CN", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_organizationName, MBSTRING_ASC, (unsigned char *)"Warmlab Inc.", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName, MBSTRING_ASC, (unsigned char *)"Dev", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName, MBSTRING_ASC, (unsigned char *)"Beijing", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_localityName, MBSTRING_ASC, (unsigned char*)"Beijing", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_pkcs9_emailAddress, MBSTRING_ASC, (unsigned char *)"inter1@warmlab.com", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char *)"Warmlab intermediate CA1", -1, -1, 0);

	exts = sk_X509_EXTENSION_new_null();
	if (exts) {
		X509V3_CTX ctx;
		X509V3_set_ctx(&ctx,  NULL, NULL, req, NULL, 0);
#if 0
		ASN1_OCTET_STRING *comment = ASN1_OCTET_STRING_new();
		ASN1_OCTET_STRING_set(comment, (unsigned char *)"my comment just for test", 24);
		ex = X509_EXTENSION_create_by_NID(&ex, NID_netscape_comment, 0, comment);
		exts = X509v3_add_ext(&exts, ex, 0);
		// Set basic constraints
		BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
		if (bc) {
			bc->ca = ca;
			//bc->pathlen = ASN1_INTEGER_new();
			//ASN1_INTEGER_set(bc->pathlen, 0);
			//X509_REQ_add1_ext_i2d(req, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT);
			//X509_REQ_add1_attr_by_NID(req, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT);
			//X509v3_add_ext(&exts, bc, 0);
			sk_X509_EXTENSION_push(exts, bc);

			BASIC_CONSTRAINTS_free(bc);
		} else {
			fprintf(stderr, "Cannot create BASIC_CONSTRAINTS\n");
		}
#endif
		if (ca)
			ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:TRUE");
		else
			ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:FALSE");
		sk_X509_EXTENSION_push(exts, ex);
		//X509_EXTENSION_free(ex);
		//X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len);
		ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
		sk_X509_EXTENSION_push(exts, ex);
		//ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always");  
		//sk_X509_EXTENSION_push(exts, ex);
		//if (ca)
			//ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment, "Intermediate CA request");
		//else
			//ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment, "General request");
		sk_X509_EXTENSION_push(exts, ex);
		//X509_EXTENSION_free(ex);
		X509_REQ_add_extensions(req, exts);
	} else {
		fprintf(stderr, "do not have any extensions.\n");
	}

	X509V3_EXT_cleanup();
	X509_REQ_sign(req, pkey, EVP_sha1());

	return req;
}

int add_ext_to_cert(X509 *cert, X509 *root, int nid, char *value)
{
	X509_EXTENSION *ex;  
	X509V3_CTX ctx;  

	X509V3_set_ctx(&ctx,root, cert, NULL, NULL, 0);  
	ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);  
	if (!ex)  
		return 0;  

	X509_add_ext(cert,ex,-1);  
	X509_EXTENSION_free(ex);  

	return 1;
}

int copy_extensions(X509 *x, X509_REQ *req, int copy_type)  
{  
	STACK_OF(X509_EXTENSION) *exts = NULL;  
	X509_EXTENSION *ext, *tmpext;  
	ASN1_OBJECT *obj;  
	int i, idx, ret = 0;  
	if (!x || !req || (copy_type == 0))  
		return 1;  
	exts = X509_REQ_get_extensions(req);  

	for(i = 0; i < sk_X509_EXTENSION_num(exts); i++)  
	{  
		ext = sk_X509_EXTENSION_value(exts, i);  
		obj = X509_EXTENSION_get_object(ext);  
		idx = X509_get_ext_by_OBJ(x, obj, -1);  
		/* Does extension exist? */  
		if (idx != -1)   
		{  
			/* If normal copy don't override existing extension */  
			if (copy_type == 1)  
				continue;  
			/* Delete all extensions of same type */  
			do  
			{  
				tmpext = X509_get_ext(x, idx);  
				X509_delete_ext(x, idx);  
				X509_EXTENSION_free(tmpext);  
				idx = X509_get_ext_by_OBJ(x, obj, -1);  
			} while (idx != -1);  
		}  
		if (!X509_add_ext(x, ext, -1))  
		{  
			sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);  

			return ret;  

		}  
	}  

	ret = 1;  
	return ret;  
}  

X509* sign_request_by_ca(X509 *root_x509, X509_REQ *req, EVP_PKEY *pkey, int ca)
{
	X509 *x509;
	STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ex;
	X509_NAME *name;
	EVP_PKEY *key;
	int len;
	unsigned char sha_hash[SHA_DIGEST_LENGTH];
	unsigned char name_hash[SHA_DIGEST_LENGTH];
	unsigned char pubkey_hash[SHA_DIGEST_LENGTH] = {0};

	key = X509_REQ_get_pubkey(req);
	if (!key) {
		fprintf(stderr, "Cannot get public key from request\n");
		return NULL;
	}

	//x509 = X509_REQ_to_X509(req, 365, pkey);
	x509 = X509_new();
	X509_set_version(x509, 2L);
	X509_set_issuer_name(x509, X509_get_subject_name(root_x509));
	name = X509_REQ_get_subject_name(req);
	X509_set_subject_name(x509, name);
	X509_gmtime_adj(X509_get_notBefore(x509), 0);
	X509_gmtime_adj(X509_get_notAfter(x509), (long)365*24*60*60);
	X509_set_pubkey(x509, key);
	EVP_PKEY_free(key);

	// Set serial number
	if (X509_NAME_digest(name, EVP_sha1(), name_hash, &len) == 1) {
		if (X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len)) {
			for (int i = 0; i < SHA_DIGEST_LENGTH; i++)
				sha_hash[i] = name_hash[i] ^ pubkey_hash[i];
			ASN1_INTEGER *serial_num = ASN1_INTEGER_new();
			if (serial_num) {
				ASN1_OCTET_STRING_set(serial_num, sha_hash, SHA_DIGEST_LENGTH);
				X509_set_serialNumber(x509, serial_num);
			} else {
				ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
			}
		} else {
			ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
		}
	} else {
		ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
	}

	//copy_extensions(x509, req, 2);
	if (ca) {
		add_ext_to_cert(x509,x509,NID_basic_constraints, "CA:TRUE");  
		add_ext_to_cert(x509,root_x509, NID_authority_key_identifier, "keyid:always,issuer:always");  
	} else {
		//add_ext_to_cert(x509,x509,NID_basic_constraints, "critical,CA:FALSE,pathlen:1");  
		add_ext_to_cert(x509,x509,NID_basic_constraints, "critical,CA:FALSE,pathlen:1");  
	}
	add_ext_to_cert(x509,x509,NID_subject_key_identifier, "hash");  
#if 0

	// Set basic constraints
	BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
	if (bc) {
		bc->ca = ca;
		//bc->pathlen = ASN1_INTEGER_new();
		//ASN1_INTEGER_set(bc->pathlen, 0);
		X509_add1_ext_i2d(x509, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT);

		BASIC_CONSTRAINTS_free(bc);
	} else {
		fprintf(stderr, "Cannot create BASIC_CONSTRAINTS\n");
	}

	// Set subject key identifier
	ASN1_OCTET_STRING *subjectKeyIdentifier = ASN1_OCTET_STRING_new();
	if (subjectKeyIdentifier) {
		if (!pubkey_hash[0]) {
			X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len);
		}
		ASN1_OCTET_STRING_set(subjectKeyIdentifier, pubkey_hash, SHA_DIGEST_LENGTH);
		X509_add1_ext_i2d(x509, NID_subject_key_identifier, subjectKeyIdentifier, 0, X509V3_ADD_DEFAULT);
		ASN1_OCTET_STRING_free(subjectKeyIdentifier);
	}

	// Set authority keyid
	AUTHORITY_KEYID *akid = AUTHORITY_KEYID_new();
	if (akid) {
		akid->issuer = GENERAL_NAMES_new();
		GENERAL_NAME *gen_name = GENERAL_NAME_new();
		gen_name->type = GEN_DIRNAME;
		gen_name->d.directoryName = X509_NAME_dup(X509_get_subject_name(x509));
		sk_GENERAL_NAME_push(akid->issuer, gen_name);
		akid->keyid = (ASN1_OCTET_STRING*)X509_get_ext_d2i(x509, NID_subject_key_identifier, NULL, NULL);
		akid->serial = ASN1_INTEGER_dup(X509_get_serialNumber(x509));

		X509_add1_ext_i2d(x509, NID_authority_key_identifier, akid, 0, X509V3_ADD_DEFAULT);

		AUTHORITY_KEYID_free(akid);
	}

	// Set netscape comment
	ASN1_OCTET_STRING *comment = ASN1_OCTET_STRING_new();
	if (comment) {
		ASN1_OCTET_STRING_set(comment, (unsigned char *)"my comment just for test", 24);
		//ex = X509_EXTENSION_create_by_NID(&ex, NID_netscape_comment, 0, comment);
		//exts = X509v3_add_ext(NULL, ex, 0);
		X509_add1_ext_i2d(x509, NID_netscape_comment, comment, 0, X509V3_ADD_DEFAULT);
		ASN1_OCTET_STRING_free(comment);
	}
#endif

	X509V3_EXT_cleanup();
	X509_sign(x509, pkey, EVP_sha1());

	return x509;
}

X509_REQ *generate_final_request(EVP_PKEY *pkey, int serv)
{
	X509_REQ *req;
	X509_NAME *name;
	STACK_OF(X509_EXTENSION) *exts;
	X509_EXTENSION *ex;
	int len;
	unsigned char sha_hash[SHA_DIGEST_LENGTH];
	unsigned char name_hash[SHA_DIGEST_LENGTH];
	unsigned char pubkey_hash[SHA_DIGEST_LENGTH] = {0};

	req = X509_REQ_new();

	X509_REQ_set_pubkey(req, pkey);

	name = X509_REQ_get_subject_name(req);
	X509_NAME_add_entry_by_NID(name, NID_countryName, MBSTRING_ASC, (unsigned char *)"CN", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_organizationName, MBSTRING_ASC, (unsigned char *)"Warmlab Inc.", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_organizationalUnitName, MBSTRING_ASC, (unsigned char *)"Dev", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_stateOrProvinceName, MBSTRING_ASC, (unsigned char *)"Beijing", -1, -1, 0);
	X509_NAME_add_entry_by_NID(name, NID_localityName, MBSTRING_ASC, (unsigned char*)"Beijing", -1, -1, 0);
	if (serv) {
		X509_NAME_add_entry_by_NID(name, NID_pkcs9_emailAddress, MBSTRING_ASC, (unsigned char *)"server@warmlab.com", -1, -1, 0);
		X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char *)"Warmlab server certificate", -1, -1, 0);
	} else {
		X509_NAME_add_entry_by_NID(name, NID_pkcs9_emailAddress, MBSTRING_ASC, (unsigned char *)"client@warmlab.com", -1, -1, 0);
		X509_NAME_add_entry_by_NID(name, NID_commonName, MBSTRING_ASC, (unsigned char *)"Warmlab client certificate", -1, -1, 0);
	}

	exts = sk_X509_EXTENSION_new_null();
	if (exts) {
		X509V3_CTX ctx;
		X509V3_set_ctx(&ctx,  NULL, NULL, req, NULL, 0);
#if 0
		ASN1_OCTET_STRING *comment = ASN1_OCTET_STRING_new();
		ASN1_OCTET_STRING_set(comment, (unsigned char *)"my comment just for test", 24);
		ex = X509_EXTENSION_create_by_NID(&ex, NID_netscape_comment, 0, comment);
		exts = X509v3_add_ext(&exts, ex, 0);
		// Set basic constraints
		BASIC_CONSTRAINTS *bc = BASIC_CONSTRAINTS_new();
		if (bc) {
			bc->ca = ca;
			//bc->pathlen = ASN1_INTEGER_new();
			//ASN1_INTEGER_set(bc->pathlen, 0);
			//X509_REQ_add1_ext_i2d(req, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT);
			//X509_REQ_add1_attr_by_NID(req, NID_basic_constraints, bc, 0, X509V3_ADD_DEFAULT);
			//X509v3_add_ext(&exts, bc, 0);
			sk_X509_EXTENSION_push(exts, bc);

			BASIC_CONSTRAINTS_free(bc);
		} else {
			fprintf(stderr, "Cannot create BASIC_CONSTRAINTS\n");
		}
#endif
		ex = X509V3_EXT_conf_nid(NULL, NULL, NID_basic_constraints, "CA:FALSE");
		sk_X509_EXTENSION_push(exts, ex);
		//X509_EXTENSION_free(ex);
		//X509_pubkey_digest(x509, EVP_sha1(), pubkey_hash, &len);
		ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_subject_key_identifier, "hash");
		sk_X509_EXTENSION_push(exts, ex);
		//ex = X509V3_EXT_conf_nid(NULL, &ctx, NID_authority_key_identifier, "keyid:always");  
		//sk_X509_EXTENSION_push(exts, ex);
		//if (serv)
			//ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment, "General server request");
		//else
			//ex = X509V3_EXT_conf_nid(NULL, NULL, NID_netscape_comment, "General client request");
		sk_X509_EXTENSION_push(exts, ex);
		//X509_EXTENSION_free(ex);
		X509_REQ_add_extensions(req, exts);
	} else {
		fprintf(stderr, "do not have any extensions.\n");
	}

	X509V3_EXT_cleanup();
	X509_REQ_sign(req, pkey, EVP_sha1());

	return req;
}

int main(int argc, char *argv[])
{
	EVP_PKEY *root_pkey, *pkey;
	EVP_PKEY *se_pkey, *cl_pkey;
	X509 *x509, *inter_x509;
	X509 *se_cert, *cl_cert;
	X509_REQ *req;
	X509_REQ *se_req, *cl_req;
	FILE *fp;

	// Generate a private key for root CA
	root_pkey = generate_PrivateKey();
	// Generate root CA
	x509 = generate_certificate(root_pkey);

	// Generate a privake key for request
	pkey = generate_PrivateKey();
	if (!pkey) {
		fprintf(stderr, "Cannot generate private key\n");
		return 1;
	}
	req = generate_request(pkey, 1);

	// Intermediate CA
	inter_x509 = sign_request_by_ca(x509, req, root_pkey, 1);

	se_pkey = generate_PrivateKey();
	se_req = generate_final_request(se_pkey, 1);

	cl_pkey = generate_PrivateKey();
	cl_req = generate_final_request(cl_pkey, 0);

	se_cert = sign_request_by_ca(inter_x509, se_req, pkey, 0);
	cl_cert = sign_request_by_ca(inter_x509, cl_req, pkey, 0);

	RSA *rsa = EVP_PKEY_get1_RSA(root_pkey);
	fp = fopen("CAtest/private/x509_key.pem", "wb");
	PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), "password", 4, NULL, NULL);
	fclose(fp);
	RSA_free(rsa);

	fp = fopen("CAtest/x509_cert.pem", "wb");
	PEM_write_X509(fp, x509);
	fclose(fp);

	fp = fopen("CAtest/x509_req.pem", "wb");
	PEM_write_X509_REQ(fp, req);
	fclose(fp);

	fp = fopen("CAtest/x509_subca.pem", "wb");
	PEM_write_X509(fp, inter_x509);
	fclose(fp);

	fp = fopen("CAtest/server_req.pem", "wb");
	PEM_write_X509_REQ(fp, se_req);
	fclose(fp);

	rsa = EVP_PKEY_get1_RSA(pkey);
	fp = fopen("CAtest/private/x509_subkey.pem", "wb");
	PEM_write_RSAPrivateKey(fp, rsa, EVP_aes_256_cbc(), "password", 4, NULL, NULL);
	fclose(fp);
	RSA_free(rsa);

	fp = fopen("CAtest/server_cert.pem", "wb");
	PEM_write_X509(fp, se_cert);
	fclose(fp);

	rsa = EVP_PKEY_get1_RSA(se_pkey);
	fp = fopen("CAtest/private/server_key.pem", "wb");
	PEM_write_RSAPrivateKey(fp, rsa, NULL, "password", 4, NULL, NULL);
	fclose(fp);
	RSA_free(rsa);

	fp = fopen("CAtest/client_cert.pem", "wb");
	PEM_write_X509(fp, cl_cert);
	fclose(fp);

	rsa = EVP_PKEY_get1_RSA(cl_pkey);
	fp = fopen("CAtest/private/client_key.pem", "wb");
	PEM_write_RSAPrivateKey(fp, rsa, NULL, "password", 4, NULL, NULL);
	fclose(fp);
	RSA_free(rsa);

	//f = BIO_new_fp(stdout, BIO_NOCLOSE);

	//PEM_write_bio_PrivateKey(f, pkey, EVP_aes_256_cbc(), "password", 4, NULL, NULL);
	//PEM_write_bio_PrivateKey(f, pkey, NULL, "password", 4, NULL, NULL);
	//PEM_write_bio_RSAPrivateKey(f, rsa, EVP_aes_256_cbc(), "password", 4, NULL, NULL);
	//BIO_flush(f);
	//BIO_free_all(f);
	//
	RSA_free(rsa);
	EVP_PKEY_free(pkey);
	X509_free(x509);
}
