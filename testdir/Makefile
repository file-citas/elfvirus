all: test

test.o: test.c
	gcc -m32 -o test.o -c test.c

test: test.o
	gcc -g -m32 -o test test.o ../testlib.so 
	cp test test0
	cp test test1


clean:
	rm -f *.o
	rm -f test test0 test1
