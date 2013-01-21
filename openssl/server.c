#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>

int main(int argc, char *argv[]) {
	pid_t pid;
	char *buf;
	size_t len = 1024;
	BIO *bio, *pop_bio;

	bio = BIO_new_accept("0.0.0.0:8080");
	if (!bio) {
		printf("BIO_new_accept error: %s\n", ERR_reason_error_string(ERR_get_error()));
		exit(1);
	}

	if (BIO_do_accept(bio) <= 0) {
		printf("BIO_do_accept error: %s\n", ERR_reason_error_string(ERR_get_error()));
		BIO_free(bio);
		exit(2);
	}

	do {
		if (BIO_do_accept(bio) <= 0) {
			printf("BIO_do_accept error: %s\n", ERR_reason_error_string(ERR_get_error()));
			BIO_free(bio);
			exit(2);
		}

		pid = fork();
		if (pid < 0) {
			perror("fork error");
			exit(9);
		} else if (pid > 0) {
			BIO_pop(bio);
		} else {
			buf = malloc(len);
			if (!buf) {
				perror("malloc");
				BIO_free_all(bio);
				exit(3);
			}

			pop_bio = BIO_pop(bio);

			while (1) {
				int x = BIO_read(pop_bio, buf, len);  
				if (!x) {
					printf("connection closed\n");
					BIO_free_all(bio);
					exit(4);
				} else if (x < 0) {
					if (!BIO_should_retry(bio)) {
						printf("cannot be retry read\n");
						BIO_free_all(bio);
						exit(5);
					}
				}

				*(buf + x) = '\0';
				if (!strcasecmp(buf, "quit"))
					break;

				strcpy(buf+x, "-Server");
				x = BIO_write(pop_bio, buf, strlen(buf));
				if (!x) {
					printf("connection closed\n");
					BIO_free_all(bio);
					BIO_free_all(pop_bio);
					exit(4);
				} else if (x < 0) {
					if (!BIO_should_retry(bio)) {
						printf("cannot be retry write\n");
						BIO_free_all(bio);
						BIO_free_all(pop_bio);
						exit(5);
					}
				}
			}
		}
	} while (1);

	BIO_free(bio);
	BIO_free_all(pop_bio);

	return 0;
}
