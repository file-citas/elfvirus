#!/bin/sh

TARGET  = elfvirus
CC      = gcc
CFLAGS  = -m32 -fomit-frame-pointer -Wall -W
LDFLAGS = -L/usr/lib32/

.PHONY: all clean

all: $(TARGET) testlib.so

elfvirus.o: elfvirus.c
	$(CC) $(CFLAGS) -c -o $@ $<

$(TARGET): elfvirus.o
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ $<


testlib.o: testlib.c
	$(CC) -c -fPIC $(CFLAGS) -o $@ $<

testlib.so: testlib.o
	$(CC) $(LDFLAGS) $(CFLAGS) -shared -o $@ $<

clean:
	rm -f *.o
	rm -f $(TARGET)
	rm -f testlib.so


