#Start of the Makefile
all: testSysCalls.o
	gcc -std=c99 -o testSysCalls testSysCalls.o -I.

runCommand.o: testSysCalls.c
	gcc -std=c99 -Wall -g -c testSysCalls.c -I.

clean:
	rm *.o

##End of the Makefile

