portscanner: portscanner.o
	gcc -o portscanner portscanner.o -lnet -lpcap -lpthread

portscanner.o: portscanner.cpp
	gcc -c portscanner.cpp

clean:
	rm portscanner.o