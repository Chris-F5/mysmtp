CFLAGS = -g -Wall
LDFLAGS = -lssl -lcrypto
OUTPUT = mysmtp
CC = gcc
OBJ = mysmtp.o

.PHONY: run clean

$(OUTPUT): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

%.o: %.c cnotec.h
	$(CC) -c $(CFLAGS) -o $@ $<

run: $(OUTPUT)
	./$(OUTPUT)
clean:
	rm -rf $(OBJ) $(OUTPUT)
