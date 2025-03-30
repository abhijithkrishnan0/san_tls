CC     = gcc
CFLAGS = -Wall -O2 -g -I$(shell brew --prefix openssl)/include
LIBS   = -L$(shell brew --prefix openssl)/lib -lssl -lcrypto

all: split

default: split.c logger.c timer.h
	$(CC) $(CFLAGS) -o split split.c logger.c $(LIBS)

clean:
	rm -f split
