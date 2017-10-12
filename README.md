# PortScanner V1.0
[![Build Status](https://travis-ci.org/Kr4t0n/PortScanner.svg?branch=master)](https://travis-ci.org/Kr4t0n/PortScanner)

This a simple prototype of portscanner using three kind of scan mode, SOCKET_SCAN, SYN_SCAN and FIN_SCAN.

# Dependency
This prototype is mainly implemented under Linux.  
Following libraries should include:

* Libnet
* Libpcap

# How to build
```
g++ -o portscanner portscanner.cpp -lpcap -lnet -lpthread
```

