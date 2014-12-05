#include <stdlib.h>
#include <stdio.h>

extern void foo();

int main(int argc, char** argv)
{
	printf("HI\n");
	foo();
	printf("foo %p\n" ,foo);
	printf("printf %p\n" ,printf);
	return 0;
}

