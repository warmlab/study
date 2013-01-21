#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

#include <sys/types.h>

void *t_start(void *data) {
	sleep(3);
}

int main() {
	int pid;
	int status;
	pthread_t tid;

	pid = fork();
	if (pid < 0) {
		perror("fork error");
		exit(-1);
	} else if (pid > 0) { // parent process
		printf("child process id: %d\n", pid);
		do {
			while((pid = waitpid(-1, &status, WNOHANG)))
				if (pid > 0)
					printf("process %d status %d\n", pid, status);

			sleep(1);

		} while(1);

		exit(0);
	}

	status = 4;
	do {
		pthread_create(&tid, NULL, t_start, NULL);
		status--;
	} while (status > 0);

	sleep(1);

	return 0;
}
