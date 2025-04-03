CC = gcc
CFLAGS = -Wall -Wextra -O2
LDFLAGS = -lpcap -lpthread

SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin

SRCS = main.c network_protection.c ui.c
OBJS = $(SRCS:.c=.o)
TARGET = openmammoth

.PHONY: all clean install uninstall

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(OBJS) -o $(TARGET) $(LDFLAGS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)

install: $(TARGET)
	install -m 755 $(TARGET) /usr/local/bin/

uninstall:
	rm -f /usr/local/bin/$(TARGET) 