# CS244B-carrot
CS244B distributed systems final project

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