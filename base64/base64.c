#include <stdint.h>

static unsigned char base64[] ="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(unsigned char *output, const unsigned char *input, const int in_len)
{
	int curr_out_len = 0;
	int i = 0;
	unsigned char a, b, c;
	output[0] = '\0';
	if (in_len > 0)
	{
		while (i < in_len)
		{
			a = input[i];
			b = (i + 1 >= in_len) ? 0 : input[i + 1];
			c = (i + 2 >= in_len) ? 0 : input[i + 2];
			if (i + 2 < in_len)
			{
				output[curr_out_len++] = (base64[(a >> 2) & 0x3F]);
				output[curr_out_len++] = (base64[((a << 4) & 0x30) + ((b >> 4) & 0xf)]);
				output[curr_out_len++] = (base64[((b << 2) & 0x3c) + ((c >> 6) & 0x3)]);
				output[curr_out_len++] = (base64[c & 0x3F]);
			}
			else if (i + 1 < in_len)
			{
				output[curr_out_len++] = (base64[(a >> 2) & 0x3F]);
				output[curr_out_len++] = (base64[((a << 4) & 0x30) + ((b >> 4) & 0xf)]);
				output[curr_out_len++] = (base64[((b << 2) & 0x3c) + ((c >> 6) & 0x3)]);
				output[curr_out_len++] = '=';
			}
			else
			{
				output[curr_out_len++] = (base64[(a >> 2) & 0x3F]);
				output[curr_out_len++] = (base64[((a << 4) & 0x30) + ((b >> 4) & 0xf)]);
				output[curr_out_len++] = '=';
				output[curr_out_len++] = '=';
			}
			i += 3;
		}
		output[curr_out_len] = '\0';
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

int main() {
	char *in, *out, *oout;
	int len, olen;

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

	return 0;
}
#endif
