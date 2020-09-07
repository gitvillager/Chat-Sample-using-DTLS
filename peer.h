#ifndef PEER_H
#define PEER_H

#include "dtlsplex.h"
#include "list.h"

void formatted_display(unsigned char *data, int length );

void peer_init();
struct dtls_peer* peer_add(struct dtls_peer* p, const struct sockaddr* addr);
struct dtls_peer* peer_get(const struct sockaddr* addr, int addrlen);

void peer_dump();
void peer_clean();

int  peer_lock();
int  peer_unlock();

#endif /* PEER_H */
