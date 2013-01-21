#include <stdio.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
	char *buf;
	size_t len = 1024;

	BIO *bio;
	if (argc < 2) {
		printf("Usage: %s <ip:port>", argv[0]);
		exit(-1);
	}
	bio = BIO_new_connect(argv[1]);
	if (!bio) {
		printf("open server error\n");
		exit(1);
	}

	if (BIO_do_connect(bio) <= 0) {
		printf("connect server error\n");
		BIO_free_all(bio);
		exit(2);
	}

	buf = malloc(len);
	if (!buf) {
		perror("malloc");
		BIO_free_all(bio);
		exit(3);
	}

	do {
		scanf("%s", buf);
		int x = BIO_write(bio, buf, strlen(buf));
		if (!x) {
			printf("connection closed\n");
			BIO_free_all(bio);
			exit(4);
		} else if (x < 0) {
			if (!BIO_should_retry(bio)) {
				printf("cannot be retry write\n");
				BIO_free_all(bio);
				exit(5);
			}
		}
		if (!strcasecmp(buf, "quit"))
			break;
		x =  BIO_read(bio, buf, len);
		if (!x) {
			printf("connection closed\n");
			BIO_free_all(bio);
			exit(6);
		} else if (x < 0) {
			if (!BIO_should_retry(bio)) {
				printf("cannot be retry read\n");
				BIO_free_all(bio);
				exit(5);
			}
		}

		*(buf + x) = '\0';

		printf("Server returned: %s\n", buf);
	} while (1);

	BIO_free_all(bio);

	return 0;
}
