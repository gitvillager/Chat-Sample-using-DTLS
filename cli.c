
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

#define PORT 2053


#include "dtlsplex.h"
#include "peer.h"
#include "simple_debug.h"

static int
makesock(int port)
{
	int sock = 0;

	struct sockaddr_in addr;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf ( stderr , "socket: %s\n", strerror (errno ));
		exit (EXIT_FAILURE);
	}


	return sock;
}

int
main(int argc, char **argv)
{

	g_simple_debug_flag = 0;

	SSL_library_init ();
	SSL_load_error_strings ();


	if (argc != 3) {
		printf("usage: %s <IPaddress> <port>\n", argv[0]);

		return 0;
	}


	int sock = makesock(PORT);

	struct sockaddr_in dst;
	memset(&dst, 0x0, sizeof(struct sockaddr_in));

	struct sockaddr* d = (struct sockaddr *) &dst;
	dst.sin_family = AF_INET;
	dst.sin_port = htons(atoi(argv[2]));

	inet_pton(AF_INET, argv[1], 
			(void *)&dst.sin_addr.s_addr);

	peer_init();

	int ret ;

	struct sockaddr s;

	socklen_t slen = 0;

#define MAXLINE     4096    /* max text line length */

	char    inputline[MAXLINE];
	char    sendline[MAXLINE], recvline[MAXLINE + 1];

	memset(inputline, 0x0, sizeof(sendline));


	while (fgets(inputline, MAXLINE, stdin) != NULL) {

		//printf("===> %s(%d) from stdio\n", inputline, strlen(inputline));


		/*  */
		if(strlen(inputline) ==0 || inputline[0] =='\n') {
			continue;
		}

		do {

			strcpy(sendline, inputline);
			
			ret = dtlssendto(sock, sendline, strlen(sendline) , 0, d, sizeof dst );

			if (ret < 0)
				fprintf ( stderr , "dtlssendto returned %d\n", ret);

			memset(recvline, 0x0, sizeof(recvline));
			int ret2 = dtlsrecvfrom(sock, recvline, MAXLINE, 0,
					(struct sockaddr *) &s, &slen);	

			//fprintf ( stderr , "2 dtlsrecvfrom returned %d\n", ret2);
			SIMPLE_DEBUG_SOCKET("dtlsrecvfrom returned %d(ret=%d)(%d)\n", ret2, ret, ret == 0 ? 1:0);
			if (ret2 > 0) {
				if(recvline[strlen(recvline)-1] == '\n')
					recvline[strlen(recvline) - 1] = '\0';
				fprintf ( stdout , "==>%s(%d)(ret=%d)(%d)\n"
						, recvline
						, (int)strlen(recvline)
						, ret, ret == 0 ? 1:0);


			}


		} while (ret == 0);


		if(strncmp(recvline, "quit", strlen(recvline))==0) {
			//if(strcmp(recvline, "quit")==0) {
			printf("quit(%s)....break\n", recvline);\
				break;
		}


		memset(inputline, 0x0, sizeof(inputline));
	} //while(fgets())


	printf("terminate\n");
	peer_clean();

	return 0;
}

