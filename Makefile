CFLAGS = -g -Wall
LDFLAGS = -lssl -lcrypto
OUTPUT = mysmtp
CC = gcc
OBJ = mysmtp.o

.PHONY: run clean

$(OUTPUT): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ)

config.h:
	cp config.def.h $@

%.o: %.c config.h
	$(CC) -c $(CFLAGS) -o $@ $<

run: $(OUTPUT)
	./$(OUTPUT)
clean:
	rm -rf $(OBJ) $(OUTPUT)
