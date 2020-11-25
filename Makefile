.PHONY : all clean
CC ?= gcc
CFLAGS = -g -O2 -Wall 
LDFLAGS = 

BIN := ./bin
TARGET := $(BIN)/test_dict

all: build $(TARGET)

build:
	-mkdir -p bin

SRC = dict.c dict.h sha256.c sha256.h siphash.c util.c util.h
$(TARGET) : $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean : 
	-rm -rf $(BIN)
