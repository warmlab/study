#include <stdint.h>

static unsigned char base64[] ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(unsigned char *output, const unsigned char *input, const int in_len)
{
	int i;
	unsigned short s = 0;
	unsigned char c, cc;
	unsigned int len = 0;
	int count = 0;
	for (i = 0; i < in_len; i++) {
		c = *(input + i);
		if (len == 0) {
			output[count++] = base64[(c & 0xFC) >> 2];
			len = 2;
			cc = c;
		} else if (len == 2) {
			output[count++] = base64[((c & 0xF0) >> 4) | ((cc & 0x3) << 4)];
			len = 4;
			cc = c;
		} else if (len == 4) {
			output[count++] = base64[((c & 0xC0) >> 6) | ((cc & 0xF) << 2)];
			output[count++] = base64[(c & 0x3F)];
			len = 0;
			cc = '\0';
		}
	}
	if (len == 2) {
		output[count++] = base64[(cc & 0x3) << 4];
		output[count++] = '=';
		output[count] = '=';
	} else if (len == 4) {
		output[count++] = base64[(cc & 0xF) << 2];
		output[count] = '=';
	}
}

void base64_encode_little_endian(unsigned char *output, const unsigned char *input, const int in_len)
{
	int i;
	int count;
	union {
		unsigned char c[4];
		int i;
	} u;

	int total = in_len / 3;

	for (i = 0, count =0; i < in_len - 2 && count < total; i+=3, count++) {
		u.c[2] = input[i];
		u.c[1] = input[i + 1];
		u.c[0] = input[i + 2];

		output[count * 4 + 0] = base64[(u.i & 0xFC0000) >> 18];
		output[count * 4 + 1] = base64[(u.i & 0x3F000) >> 12];
		output[count * 4 + 2] = base64[(u.i & 0xFC0) >> 6];
		output[count * 4 + 3] = base64[u.i & 0x3F];
	}

	int remain = in_len % 3;
	if (remain == 1) {
		u.c[2] = input[in_len - 1];
		u.c[1] = 0;
		u.c[0] = 0;

		output[count * 4 + 0] = base64[(u.i & 0xFC0000) >> 18];
		output[count * 4 + 1] = base64[(u.i & 0x3F000) >> 12];
		output[count * 4 + 2] = '=';
		output[count * 4 + 3] = '=';
	} else if (remain == 2) {
		u.c[2] = input[in_len - 2];
		u.c[1] = input[in_len - 1];
		u.c[0] = 0;

		output[count * 4 + 0] = base64[(u.i & 0xFC0000) >> 18];
		output[count * 4 + 1] = base64[(u.i & 0x3F000) >> 12];
		output[count * 4 + 2] = base64[(u.i & 0xFC0) >> 6];
		output[count * 4 + 3] = '=';
	}
}

void base64_decode(unsigned char *output, const unsigned char *input, const int inplen)
{
	static int map[256] = {0};
	//static unsigned char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	//size_t inplen = strlen(input);
	int words = (inplen+3)/4;
	int i=0, j=0;
	int word = 0;
	const char *p = input;
	int padnum = 0;
	int cur_pos = 0;

	for (i = 0; i < 64; ++i)
	{
		map[(int)base64[i]]=i;
	}
	if(input[inplen - 1] == '=') padnum = 1;
	if(input[inplen - 1] == '=' && input[inplen - 2] == '=') padnum = 2;

	for(i=0; i<words; i++)
	{
		word = 0;
		word |= map[(int)*p++];
		word <<= 6;
		word |= map[(int)*p++];
		word <<= 6;
		word |= map[(int)*p++];
		word <<= 6;
		word |= map[(int)*p++];
		output[cur_pos++] = word >> 16 & 0xFF;

		if (i + 1 == words && padnum == 2)
			break;
		output[cur_pos++] = word >> 8 & 0xFF;

		if (i + 1 == words && padnum == 1)
			break;
		output[cur_pos++] = word & 0xFF;
	}
}

#if 1
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
	char *in, *out, *oout;
	int len, olen;
	int fd, fd1;
	ssize_t bytes_read;
	char buf[8192], buf_base64[8192 << 1];

	in = "abcdefth";
	len = strlen(in);
	out = malloc(len * 4 / 3 + 1);

	printf("original: %s\n", in);
	base64_encode(out, in, len);
	printf("after base64_encode: %s\n", out);

	olen = strlen(out);
	oout = malloc(len + 1);
	base64_decode(oout, out, olen);
	printf("after base64_decode: %s\n", oout);

	fd = open("a.txt", O_RDONLY);
	//fd1 = open("c1.txt", O_WRONLY | O_CREAT, 0644);

time_t time1 = time(NULL);
	while ((bytes_read = read(fd, buf, 8192))) {
		base64_encode(buf_base64, buf, (int)bytes_read);
		//write(fd1, buf_base64, strlen(buf_base64));
	}

time_t time2 = time(NULL);
	close(fd);
	//close(fd1);
	fd = open("a.txt", O_RDONLY);
	//fd1 = open("c2.txt", O_WRONLY | O_CREAT, 0644);
time_t time3 = time(NULL);
	while ((bytes_read = read(fd, buf, 8192))) {
		base64_encode_little_endian(buf_base64, buf, bytes_read);
		//write(fd1, buf_base64, strlen(buf_base64));
	}

time_t time4 = time(NULL);
	close(fd);
	//close(fd1);

	printf("time: %lu, %lu\n", time2 - time1, time4 - time3);

	return 0;
}
#endif
