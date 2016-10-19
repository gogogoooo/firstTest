all: test.c 
	gcc -g -Wall -o test test.c -lpcap -lnet 
clean:  
	rm -rf *.o poll
