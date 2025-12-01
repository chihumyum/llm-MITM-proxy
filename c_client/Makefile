CC = gcc

CFLAGS = -Wall -Wextra -Werror -O2 -flto -fno-plt -fno-asynchronous-unwind-tables
LDFLAGS = -flto -s
LIBS = -lnsl -lssl -lcrypto -pthread

# SRC = main\.c
SRC = proxy_single.c
OBJ = $(SRC:.c=.o)
TARGET = proxy

$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

.PHONY: clean
clean:
	rm -f $(OBJ) $(TARGET)
