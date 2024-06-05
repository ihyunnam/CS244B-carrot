# Carrot: A Distributed Interposition Library for Networking and File Systems

Inspired by Parrot, we aim to build an interposition library that captures syscalls and distributes them to different machines. The library will leverage `ptrace` and `seccomp` to capture networking and file system calls. On the networking side, our motivation is to bypass censorship. More broadly, we are creating an almost VPN-like service that can bypass firewalls and access websites that a machine cannot individually access by interposing on `sendto` and `recvfrom` and sending the request to multiple machines. On the file system side, the goal will be to reroute open, write, close, and other syscalls to other machines such that the files don’t even live on the machine. As a result, we can simulate things such as compiling a file “locally” but have the compiler running on a remote machine. The implementation will be done in C++, and our presentation will be primarily demo + design decision oriented (i.e., effects of distributing networking HTTP requests to multiple machines, how we chose which machine to store different remote files on, etc.).

## To Run

Install `g++` and `make`:
```bash
sudo apt install g++ make
```

Then run:
```bash
make
./main <ROLE_PROGRAM>
```

### Notes on Protobuf

First, you need to install the [protobuf compiler](https://grpc.io/docs/protoc-installation/). From there, you can run `protoc` on the `message.proto` file:

```bash
protoc -I=. --cpp_out=./messages ./message.proto
```

Compiling `protobuf.cpp` will allow you test out serializing and deserializing a message.