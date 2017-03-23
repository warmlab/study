#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <string.h>

int get_if_addr(const char* if_name, struct in_addr *addr)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, if_name);
	if (!ioctl(sock, SIOCGIFADDR, &ifr)) {
		sin = (struct sockaddr_in *)&ifr.ifr_addr;
		memcpy(addr, &(sin->sin_addr), sizeof(sin->sin_addr));
		return 0;
	} else
		perror("ioctl SIOCGIFADDR");
		return -1;
}

int set_if_addr(const char* if_name, const char* s_addr)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_in *sin;

	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		perror("socket");
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	strcpy(ifr.ifr_name, if_name);
	sin = (struct sockaddr_in *)&ifr.ifr_addr;
	sin->sin_family = AF_INET;
	inet_aton(s_addr, &(sin->sin_addr));
	if (!ioctl(sock, SIOCSIFADDR, &ifr)) {
		return 0;
	} else
		perror("ioctl SIOCSIFADDR");
		return -1;
}

#include <stdio.h>

int main(int argc, char* argv[])
{
	struct in_addr addr;
	set_if_addr("eth0", "10.1.1.55");
	get_if_addr("eth0", &addr);
	printf("ip: %s\n", inet_ntoa(addr));
}
