#Start of the Makefile
all: virusScanner.o 
	gcc -std=c99 -o virusScanner viruScanner.o -I.	

virusScanner.o: virusScanner.c
	gcc -std=c99 -Wall -g -c virusScanner.c -I.

clean:
	rm *.o

##End of the Makefile

