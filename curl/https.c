#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <curl/curl.h>

/*
int curl_debug_callback(CURL *curl, curl_infotype infotype, char *buf, size_t len, void *userdata)
{
	printf("buf: %s\b", buf);
	printf("data: %s\n", userdata);
}
*/

int write_callback(char *ptr, size_t size, size_t nmemb, void *userdata)
{
	int fd = (int)(long)userdata;

	write(fd, ptr, size * nmemb);
}

int main(int argc, char *argv[])
{
	CURL *curl;
	CURLcode rc;

	curl_global_init(CURL_GLOBAL_DEFAULT);

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, argv[1]);
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
		//curl_easy_setopt(curl, CURLOPT_HEADER, 1L);

		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
		curl_easy_setopt(curl, CURLOPT_SSLCERT, "/home/xli/warmlab.com/warmlab.com.pem");
		curl_easy_setopt(curl, CURLOPT_SSLKEY, "/home/xli/warmlab.com/warmlab.com.key");
		curl_easy_setopt(curl, CURLOPT_CAINFO, "/home/xli/warmlab.com/cacert.pem");
		curl_easy_setopt(curl, CURLOPT_CAPATH, "/home/xli/warmlab.com");

		curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		//curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_debug_callback);
		//int fd = open("data", O_CREAT | O_WRONLY | O_TRUNC, 0644);
		//curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		//curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)(long)fd);
		FILE *fph = fopen("data-header", "w");
		curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, fwrite);
		curl_easy_setopt(curl, CURLOPT_HEADERDATA, fph);
		FILE *fp = fopen("data", "w");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fwrite);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);

		rc = curl_easy_perform(curl);

		if (rc != CURLE_OK)
			fprintf(stderr, "curl_easy_perform() failed %s\n",
					curl_easy_strerror(rc));

		//close(fd);
		fclose(fp);
		fclose(fph);
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();

	return 0;
}
