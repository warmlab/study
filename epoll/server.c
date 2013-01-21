#include <stdio.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define MAXLINE 10
#define LISTENQ 20
#define SERV_PORT 5000

int main(int argc, char *argv[])
{
	int i, maxi, listenfd, connfd, sockfd, epfd, nfds;
	unsigned short portnumber;
	ssize_t n;
	char line[MAXLINE];
	socklen_t clilen;

	if (2 == argc) {
		if ((portnumber = atoi(argv[1])) < 0) {
			fprintf(stderr, "Usage: %s <port>\n", argv[0]);
			return 1;
		}
	} else {
		fprintf(stderr, "Usage: %s <port>\n", argv[0]);
		return 1;
	}

	struct epoll_event ev, events[20];
	epfd = epoll_create(256);
	struct sockaddr_in clientaddr;
	struct sockaddr_in serveraddr;

	listenfd = socket(AF_INET, SOCK_STREAM, 0);

	ev.data.fd = listenfd;
	ev.events = EPOLLIN | EPOLLET;

	epoll_ctl(epfd, EPOLL_CTL_ADD, listenfd, &ev);
	memset(&serveraddr, 0, sizeof(struct sockaddr_in));
	serveraddr.sin_family = AF_INET;
	char *local_addr = "127.0.0.1";
	inet_aton(local_addr, &(serveraddr.sin_addr));
	serveraddr.sin_port = htons(portnumber);
	bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in));
	listen(listenfd, LISTENQ);
	maxi = 0;

	for(;;) {
		nfds = epoll_wait(epfd, events, 20, -1);
		for (i = 0; i < nfds; i++) {
			if (events[i].data.fd == listenfd) {
				clilen = sizeof(struct sockaddr_in);
				connfd = accept(listenfd, (struct sockaddr *)&clientaddr, &clilen);
				if (connfd < 0) {
					perror("connfd error");
					exit(1);
				}

				char str[32];
				inet_ntop(AF_INET, &(clientaddr.sin_addr), str, clilen, 32);
				printf("accept a new connection from %s\n", str);

				ev.data.fd = connfd;
				ev.events = EPOLLIN | EPOLLET;

				epoll_ctl(epfd, EPOLL_CTL_ADD, connfd, &ev);
			} else if (events[i].events & EPOLLIN) {
				printf ("EPOLLIN...........\n");
				if ((sockfd = events[i].data.fd) < 0)
					continue;
				else if ((n = read(sockfd, line, MAXLINE)) < 0) {
					if (errno == ECONNRESET) {
						close(sockfd);
						events[i].data.fd = -1;
					} else
						printf("read line error");
				} else if (n == 0) {
					close(sockfd);
					events[i].data.fd = -1;
				}
				line[n] = '\0';
				printf("read data: %s\n", line);

				ev.data.fd = sockfd;
				ev.events = EPOLLOUT | EPOLLET;

				epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
			} else if (events[i].events & EPOLLOUT) {
				printf ("EPOLLOUT..........\n");
				sockfd = events[i].data.fd;
				write(sockfd, line, n);
				printf("write data: %s\n", line);
				ev.data.fd = sockfd;
				ev.events = EPOLLIN | EPOLLET;

				epoll_ctl(epfd, EPOLL_CTL_MOD, sockfd, &ev);
			}
		}
	}

	return 0;
}
