/*
 */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pthread.h>
#include <unistd.h>

#include "peer.h"
#include "simple_debug.h"

struct dl_list list_head;
static pthread_mutex_t peer_mutex_lock;

#define INVALID_SESSION_TIMEOUT 30 /* second  */
#define IS_EXPIRE(ts,to) ((ts + to) <= jiffies)

time_t jiffies;

/*
 * garbage collector
 *
 * How do I know that peer is closed ?(I'm UDP)
 */
static void run_gc ()
{
	struct dtls_peer *t3, *tmp3;

	while (1)
	{
		sleep(1);         /* 1 sec interval */

		peer_lock();

		jiffies = time(NULL);/* current time*/


		dl_list_for_each_safe(t3, tmp3, &list_head, struct dtls_peer, list) {

			/* if session expired, delete it*/
			if(IS_EXPIRE(t3->time_stamp, INVALID_SESSION_TIMEOUT)) {

				struct sockaddr_in *addr_in = (struct sockaddr_in *)&t3->addr;

				SIMPLE_DEBUG_PEER("%s() %s:%d\n"
						, __func__
						,inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port)
					  );

				SSL_shutdown(t3->ssl);
				SSL_free(t3->ssl);
				BIO_free(t3->bio_network);


				dl_list_del(&t3->list);
				free(t3);

			}

		} //dl_list_for_each_safe


		peer_unlock();

	}/* while(1) */

}


void peer_init()
{

	dl_list_init(&list_head);

	int result = pthread_mutex_init(&peer_mutex_lock, NULL);

	pthread_t tid;
	/* create timer thread*/
	result = pthread_create (&tid, NULL, (void *) &run_gc, (void *)NULL);
	if (result != 0)
	{
		fprintf (stderr, "%s(): thread creation fail.\n", __func__);
		exit (1);
	}


}

struct dtls_peer* peer_add(struct dtls_peer* p, const struct sockaddr* addr)
{

	struct dtls_peer *t;

	t = (struct dtls_peer *)malloc(sizeof(*t));
	if (t == NULL)
		return NULL;

	memset(t, 0x0, sizeof(*t));


	//strcpy(t->keyword, start);
	//struct sockaddr addr;
	memcpy(&t->addr, addr, sizeof(struct sockaddr));

	t->bio_network = p->bio_network;
	t->bio_internal = p->bio_internal;
	t->ssl = p->ssl;

	t->time_stamp = jiffies;

	dl_list_add_tail(&list_head, &t->list);

	return t;
}

struct dtls_peer* peer_get(const struct sockaddr* addr, int addrlen)
{

	struct dtls_peer *t3, *tmp3;

	dl_list_for_each_safe(t3, tmp3, &list_head, struct dtls_peer, list) {


		struct sockaddr_in *addr_in = (struct sockaddr_in *)&t3->addr;
		struct sockaddr_in *addr_in2 = (struct sockaddr_in *)addr;

		SIMPLE_DEBUG_PEER("%s() %s:%d vs %s:%d\n", __func__
			,inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port)
			,inet_ntoa(addr_in2->sin_addr), ntohs(addr_in2->sin_port)
		  );

		if(memcmp((struct sockaddr *)&t3->addr, 
					addr, 
					sizeof(struct sockaddr))==0)
					//8)==0) /* !!! WARN !!! */
		{
			SIMPLE_DEBUG_PEER("*** match ***  %s() %s(port %d)\n", __func__,
					inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port)
				  );

			/* update timestamp */
			t3->time_stamp = jiffies;
			
			return t3;

	


		}

	} //dl_list_for_each_safe


	SIMPLE_DEBUG_PEER("%s() return NULL\n", __func__);

	return NULL;



}

void peer_dump()
{
	struct dtls_peer *t3, *tmp3;

	dl_list_for_each_safe(t3, tmp3, &list_head, struct dtls_peer, list) {

		struct sockaddr_in *addr_in = (struct sockaddr_in *)&t3->addr;

		printf("%s() %s:%d\n"
				, __func__
				,inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port)
		  );
	} //dl_list_for_each_safe

}


void peer_clean()
{


	struct dtls_peer *t2, *tmp2;
	dl_list_for_each_safe(t2, tmp2, &list_head, struct dtls_peer, list) {

		SSL_shutdown(t2->ssl);
		SSL_free(t2->ssl);
		BIO_free(t2->bio_network);

		dl_list_del(&t2->list);

		free(t2);
	}

}


int  peer_lock()
{
	return(pthread_mutex_lock(&peer_mutex_lock));
}


int peer_unlock()
{
	return(pthread_mutex_unlock(&peer_mutex_lock));
}
