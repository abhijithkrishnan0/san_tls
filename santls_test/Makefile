CC     = gcc
CFLAGS = -Wall -O2 -g \
         -I$(shell brew --prefix openssl)/include \
         -I$(shell brew --prefix pbc)/include

LIBS   = -L$(shell brew --prefix openssl)/lib \
         -L$(shell brew --prefix pbc)/lib \
         -lpbc -lgmp -lssl -lcrypto

all: santls

santls: santls.c logger.c timer.h
	$(CC) $(CFLAGS) -o santls santls.c logger.c $(LIBS)

clean:
	rm -f santls
