/*
* Copyright (c) 2006 Nicolas Bernard
* All rights reserved.
*
* Permission to use, copy, modify, and distribute this software for any
* purpose with or without fee is hereby granted, provided that the above
* copyright notice and this permission notice appear in all copies.
*
* THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
* WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
* MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
* ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
* ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
* OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*
*/
#include <sys/types.h>
#include <sys/socket.h>

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

#include <openssl/dh.h>
#include <openssl/err.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dtlsplex.h"

#include "peer.h"
#include "simple_debug.h"

unsigned int g_simple_debug_flag;

static SSL_CTX *server_ctx = NULL;
static SSL_CTX *client_ctx = NULL;

static void dtls_info_callback (const SSL *ssl, int where, int ret)
{

	const char *str = NULL;
	int w=0;

	w = where & ~SSL_ST_MASK;

	str = where & SSL_ST_CONNECT ? "connect" : where & SSL_ST_ACCEPT ? "accept" : "undefined";
	if (where & SSL_CB_LOOP)
	{
		SIMPLE_DEBUG_HS("SSL state [\"%s\"]: %s\n", str, SSL_state_string_long (ssl));

	}
	else if (where & SSL_CB_ALERT)
	{
		SIMPLE_DEBUG_HS("SSL: alert [\"%s\"]: %s : %s\n", where & SSL_CB_READ ? "read" : "write", \
				SSL_alert_type_string_long (ret), SSL_alert_desc_string_long (ret));

	}

	else if (where & SSL_CB_HANDSHAKE_START) {




	}

	else if (where & SSL_CB_HANDSHAKE_DONE) {
		SIMPLE_DEBUG_HS ("SSL state [\"%s\"]: %s... \n", str, SSL_state_string_long (ssl));
	}

   
}

static int dtls_verify_callback (int ok, X509_STORE_CTX *ctx) {
	/* This function should ask the user
	 * if he trusts the received certificate.
	 * Here we always trust.
	 */
	return 1;
}

static SSL *
SSL_create(SSL_CTX* ctx, BIO* conn, bool client)
{
	assert (ctx != NULL);
	assert (conn != NULL);

	SSL *ssl = NULL;

	ssl = SSL_new(ctx);
	if ( ssl == NULL) {
		return NULL;
	}
	if ( client )
		SSL_set_connect_state(ssl);
	else
		SSL_set_accept_state(ssl);

	SSL_set_bio( ssl , conn, conn);

	return ssl;
}


/*
	modify native code to use mutual authentication of server & client.

 */
static SSL_CTX *
create_ctx_server()
{

	SSL_CTX* ctx = SSL_CTX_new(DTLSv1_2_server_method()); //v1.2

	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	int err = SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES256-GCM-SHA384");
	if (err != 1) {
		fprintf ( stderr , "DTLS: unable to load ciphers, exiting\n");
		exit (1);
	}

	if (!SSL_CTX_use_certificate_file(ctx, "server_certkey.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "server_certkey.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");

	
	FILE * paramfile = fopen("server_certkey.pem", "r");

	if (paramfile == NULL) {

		fprintf ( stderr , "Error opening the DH file: %s\n",
				strerror (errno ));
		return NULL;
	}

	DH* dh_1024 = PEM_read_DHparams(paramfile, NULL, NULL, NULL);

	fclose (paramfile );

	if (dh_1024 == NULL) {
		fprintf ( stderr , "Error reading the DH file\n");
		return NULL;
	}
	err = SSL_CTX_set_tmp_dh(ctx, dh_1024);
	if (err != 1) {
		fprintf ( stderr , "createctx: unable to set DH parameters\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		ctx = NULL;
		return NULL;
	}

	DH_free(dh_1024);
	dh_1024 = NULL;


	/* Client has to authenticate */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE, dtls_verify_callback);

	SSL_CTX_set_info_callback (ctx, &dtls_info_callback); //debug

	return ctx;
}

static SSL_CTX *
create_ctx_client()
{

	SSL_CTX* ctx = SSL_CTX_new(DTLSv1_2_client_method()); //v1.2

	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	int err = SSL_CTX_set_cipher_list(ctx, "DHE-RSA-AES256-GCM-SHA384");

	if (err != 1) {
		fprintf ( stderr , "DTLS: unable to load ciphers, exiting\n");
		exit (1);
	}


	if (!SSL_CTX_use_certificate_file(ctx, "client_certkey.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no certificate found!");

	if (!SSL_CTX_use_PrivateKey_file(ctx, "client_certkey.pem", SSL_FILETYPE_PEM))
		printf("\nERROR: no private key found!");

	if (!SSL_CTX_check_private_key (ctx))
		printf("\nERROR: invalid private key!");


	FILE * paramfile = fopen("client_certkey.pem", "r");

	if (paramfile == NULL) {

		fprintf ( stderr , "Error opening the DH file: %s\n",
				strerror (errno ));
		return NULL;
	}

	DH* dh_1024 = PEM_read_DHparams(paramfile, NULL, NULL, NULL);

	fclose (paramfile );

	if (dh_1024 == NULL) {
		fprintf ( stderr , "Error reading the DH file\n");
		return NULL;
	}


	err = SSL_CTX_set_tmp_dh(ctx, dh_1024);
	if (err != 1) {
		fprintf ( stderr , "createctx: unable to set DH parameters\n");
		ERR_print_errors_fp(stderr);
		SSL_CTX_free(ctx);
		ctx = NULL;
		return NULL;
	}

	SSL_CTX_set_info_callback (ctx, &dtls_info_callback); //debug

	return ctx;
}


static struct dtls_peer *
dtlsnewpeer(const struct sockaddr *so, bool client)
{

	assert (so != NULL);


	int err = 0;	

	if(client) {

		if (client_ctx == NULL) {

			client_ctx = create_ctx_client();
			if (client_ctx == NULL) {
				fprintf ( stderr , "dtlsnewpeer: unable to create client CTX\n");

				return NULL;
			}

		}

	} else {

		if (server_ctx == NULL) {

			server_ctx = create_ctx_server();
			if (server_ctx == NULL) {
				fprintf ( stderr , "dtlsnewpeer: unable to create server CTX\n");

				return NULL;
			}
		}
	}

	struct dtls_peer p;
	memset(&p, 0x0, sizeof(struct dtls_peer));
	err = BIO_new_bio_pair(&p.bio_network, MTU, &p.bio_internal, MTU);

	if (err != 1) {
		fprintf ( stderr , "dtlsnewpeer: unable to create bio pair\n");
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	if(client)
		p.ssl = SSL_create(client_ctx, p.bio_internal, client);
	else
		p.ssl = SSL_create(server_ctx, p.bio_internal, client);

	if (p.ssl == NULL) {
		BIO_free(p.bio_network);
		BIO_free(p.bio_internal);
		return NULL;
	}

	return peer_add(&p, so);

}


ssize_t
dtlssendto(int s, const void *msg, size_t len, int flags ,
		const struct sockaddr *to, socklen_t tolen)
{

	ssize_t ret = -1;
	int err=0;

	unsigned char* tbuf[MTU] = {0};

	ssize_t retv = -10;

	if (len > MTU) {
		/* what about TLS encapsulation size? */
		errno = EMSGSIZE;
		return -2;
	}

	//peer_dump();

	peer_lock();
	struct dtls_peer *p = peer_get(to, tolen );
	peer_unlock();

	if (p == NULL) {
		SIMPLE_DEBUG_PEER("unknown peer!!\n");


		peer_lock();
		p = dtlsnewpeer(to, true);
		peer_unlock();

		if (p == NULL) {
			fprintf ( stderr , "dtlssendto: peer creation failed \n");
			return -3;
		}
		err = SSL_connect(p->ssl);
		retv = 0;
	} else {

		err = SSL_write(p->ssl, msg, len);
		if (err != len) {
			int ret = SSL_get_error(p->ssl, err);
			fprintf ( stderr , "dtlssendto: SSL write/connect returned %d"
					" (len was %d): error %d\n", (int)err, (int)len, (int)ret );
			ERR_print_errors_fp(stderr);
		}

		retv = len;
	}


	ret = BIO_read(p->bio_network, tbuf, MTU);

	if (ret <= 0) {
		if (ret < 0)
			fprintf ( stderr , "dtlssendto: BIO read error (%d)\n",
					(int)ret );
		return 0;
	}

	err = sendto(s, tbuf, ret , flags , to, tolen );

	if (err != ret) {
		fprintf ( stderr , "dtlssendto: sendto: %s\n",
				strerror (errno ));
		return -1;
	}
	return retv;
}

static struct dtls_peer *
socktobssl(int s, int flags )
{
	ssize_t ret = -1;

	unsigned char* tbuf[MTU] = {0};
	//struct sockaddr_storage ifrom;
	struct sockaddr ifrom;
	socklen_t ifromlen = sizeof ifrom;

	ret = recvfrom(s, tbuf, MTU, flags, (struct sockaddr*) &ifrom,
			&ifromlen);


	if (ret == -1) {
		fprintf ( stderr , "dtlsrecvfrom: recvfrom: %s\n",
				strerror (errno ));
		return NULL;
	}

#if 0
	struct sockaddr * aa =  (struct sockaddr *)&ifrom;

	struct sockaddr_in * addr_in = (struct sockaddr_in *)aa;

	printf("aaa %s() packet recevice from  %s:%d\n", __func__ ,inet_ntoa(addr_in->sin_addr), ntohs(addr_in->sin_port));
#endif

	peer_lock();
	struct dtls_peer *p = peer_get((struct sockaddr *) &ifrom, ifromlen);
	peer_unlock();
	if (p == NULL) {
		SIMPLE_DEBUG_PEER("unknown peer!!!\n");

		//formatted_display((unsigned char *)&ifrom, sizeof(struct sockaddr) )  ;

		peer_lock();
		p = dtlsnewpeer((struct sockaddr *) &ifrom, false);
		peer_unlock();
		if (p == NULL)
			return NULL;
	}

#ifdef DBG_DTLS
	fprintf ( stderr , "Writing %d octet(s) to the bio_network\n", (int)ret );
#endif

	int nret = BIO_write(p->bio_network, tbuf, ret);
	assert (nret == ret);
	int needed = BIO_get_read_request(p->bio_network);
	if (needed > 0) {
		fprintf ( stderr , "dtlsrecvfrom: Still %d octet(s) needed... \n",
				needed);
		return NULL;
	}
	return p;
}


static int
ssltobuf (int s, void * buf, size_t len, int flags ,
		struct sockaddr *from, socklen_t *fromlen, struct dtls_peer * p)
{
	assert (p != NULL);

	int ret2 = SSL_read(p->ssl, buf, len);

	if (ret2 < 0) {
		int err = 0;
		err = SSL_get_error(p->ssl, err);
#if 0
		/* original code */
		fprintf ( stderr , "%s() SSL read: returned %d, error %d\n", __func__, ret2, err );
		ERR_print_errors_fp(stderr);
#else
		if (err !=SSL_ERROR_NONE && err != SSL_ERROR_SYSCALL ) {
			fprintf ( stderr , "SSL read: returned %d, code %d\n", ret2, err );
			ERR_print_errors_fp(stderr);
		} else
			ret2=0;

#endif
	}

	int retb = 0;

	if ((retb = BIO_ctrl_pending(p->bio_network)) > 0) {
#ifdef DBG_DTLS
		fprintf ( stderr , "sending pending data (%d octets to send)\n",
				retb );
#endif

		unsigned char * tbuf[MTU] = {0};
		int ret3 = BIO_read(p->bio_network, tbuf, MTU);

		if (ret3 != retb)
			fprintf ( stderr , "dtlsrecvfrom: warning "
					"datatosend > MTU, %d != %d\n", ret3, retb);

		retb = sendto(s, tbuf, ret3, flags , (struct sockaddr *) &p->addr,
				sizeof(struct sockaddr)
				);

		if (retb < 0) {
			fprintf ( stderr , "sendto: %s\n", strerror (errno ));
		}
		assert (ret3 == retb);
		assert (ret2 <= 0);
		return dtlsrecvfrom(s, buf, len, flags , from, fromlen);
	}

	assert (retb == 0);
	if (ret2 < 0)
		return -1;

	if (from != NULL && fromlen != NULL) {

		memcpy(from, &p->addr, sizeof(struct sockaddr));

		*fromlen = sizeof(struct sockaddr);
	}

	return (ssize_t) ret2;

}



ssize_t
dtlsrecvfrom(int s, void *buf, size_t len, int flags , struct sockaddr *from,
		socklen_t *fromlen)
{
	struct dtls_peer *p = NULL;
	p = socktobssl(s, flags );
	if (p != NULL)
		return ssltobuf(s, buf, len, flags , from, fromlen, p);

	return -1;
}
