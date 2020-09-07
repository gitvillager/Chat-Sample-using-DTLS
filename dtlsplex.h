
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

#ifndef DTLSPLEX_H
#define DTLSPLEX_H

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "list.h"

#define MTU 1500
ssize_t dtlsrecvfrom(int s, void *buf, size_t len, int flags , struct sockaddr *from, socklen_t *fromlen);
ssize_t dtlssendto(int s, const void *msg, size_t len, int flags , const struct sockaddr *to, socklen_t tolen );

/*
https://www.openssl.org/docs/manmaster/crypto/BIO_s_bio.html

BIO *internal_bio, *network_bio;
 ...
 BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0);
 SSL_set_bio(ssl, internal_bio, internal_bio);
 SSL_operations(); //e.g SSL_read and SSL_write
 ...

 application |   TLS-engine
    |        |
    +----------> SSL_operations()
             |     /\    ||
             |     ||    \/
             |   BIO-pair (internal_bio)
             |   BIO-pair (network_bio)
             |     ||     /\
             |     \/     ||
    +-----------< BIO_operations()
    |        |
    |        |
   socket

  ...
  SSL_free(ssl);               // implicitly frees internal_bio 
  BIO_free(network_bio);
  ...
*/


struct dtls_peer {

	struct dl_list list;

	struct sockaddr addr;

	BIO * bio_network;  /* bio*/
	BIO * bio_internal; /* _b2*/
	SSL * ssl;

	time_t time_stamp; /* to check activity */

};
#endif /* ! DTLSPLEX_H */
