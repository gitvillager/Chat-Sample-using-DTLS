
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

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

#include  "simple_debug.h"

static int
makesock(int port)
{
	int sock = 0;
	struct sockaddr_in addr;
	addr.sin_family      = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		fprintf ( stderr , "socket: %s\n", strerror (errno ));
		exit (EXIT_FAILURE);
	}

	if (bind(sock, (struct sockaddr *) &addr, sizeof addr)) {
		fprintf ( stderr , "bind: %s\n", strerror (errno ));
		exit (EXIT_FAILURE);
	}

	return sock;
}

int
main()
{

	//g_simple_debug_flag = SIMPLE_DEBUG_FLAG_ALLON;
	g_simple_debug_flag = 0;

	peer_init();

	SSL_library_init ();
	SSL_load_error_strings ();

	int sock = makesock(PORT);

	printf("binding(port %d)...\n", PORT);

	while(1) {

		char buf[256] = {0};

		//struct sockaddr_storage s;
		struct sockaddr s;

		socklen_t slen = 0;

		int ret = dtlsrecvfrom(sock, buf, 256, 0,
				(struct sockaddr *) &s, &slen);

		SIMPLE_DEBUG_SOCKET("dtlsrecvfrom returned %d\n", ret);

		if(buf[strlen(buf)-1] == '\n')
			buf[strlen(buf) - 1] = '\0';

		if(strlen(buf) && strncmp(buf, "quit", strlen(buf)==0)) {
			printf("quit(%d)....\n", (int)strlen(buf));\
				break;
		}


		fprintf ( stderr , "echo BACK [%s]\n", buf);

		/* echo back */
		ret = dtlssendto(sock, buf, strlen (buf), 0,
				(struct sockaddr *) &s, slen);


		SIMPLE_DEBUG_SOCKET("dtlssendto returned %d\n", ret);


		if(strncmp(buf, "quit", strlen(buf))==0) {
			printf("quit(%s)....break\n", buf);
			break;
		}

		memset(buf, 0x0, sizeof(buf));
	}/* while(1) */

	printf("terminate\n");
	peer_clean();

	return 0;

}

