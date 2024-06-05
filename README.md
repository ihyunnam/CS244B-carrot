# Carrot: A Distributed Interposition Library for Networking and File Systems

Inspired by Parrot, we're building Carrot, an interposition library that captures file and networking system calls and distributes them across machines.

## Set-Up

First, install necessary dependencies:
```bash
sudo apt-get update
sudo apt install g++ libprotobuf-dev libcurl4-openssl-dev libssl-dev libcrypto++-dev libresolv-dev
```

Then, set up the protobufs:
```bash
cd protobufs
protoc -I=. --cpp_out=./messages ./message.proto
protoc -I=. --cpp_out=./files ./file.proto
```

Finally, compile all of the files:
```bash
make
```

## To Run:

### File System Calls

To interpose on file system calls, look at the folder `fsc`. On one machine, run the receiver:
```bash
fsc/file_receiver
```

On another machine, run the interposition library on top of an executable doing file system calls
```bash
fsc/file_carrot fsc/file_test1
```

### Networking System Calls

To interpose on networking system calls, look at the folder `nsc`. On one machine, run the receiver:
```bash
nsc/networking_receiver
```

On another machine, run the interposition library on top of an executable doing file system calls
```bash
nsc/networking_carrot nsc/curl http://www.example.com
```