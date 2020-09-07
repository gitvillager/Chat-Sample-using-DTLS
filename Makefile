#
#
#

CC=$(CROSS_COMPILE)gcc
SSL_LIB+= -lssl -lcrypto -ldl
LIB+= $(SSL_LIB) -ldl -lpthread
CFLAGS=-Wall -g $(INC)

all:udpserv udpcli

udpserv: serv.o dtlsplex.o peer.o
	@echo "udpserver"
	$(CC) -o udpserver $(CFLAGS) serv.o dtlsplex.o peer.o $(LIB)

udpcli: cli.o dtlsplex.o
	@echo "udpcli"
	$(CC) -o udpcli $(CFLAGS) cli.o dtlsplex.o peer.o $(LIB)

.c.o:
	$(CC) $(CFLAGS) -c $<

cp:
	cp udpserver /tmp/
	cp udpcli   /tmp/

clean:
	rm -rf udpserver udpcli core *.o
