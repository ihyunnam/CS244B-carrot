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

### Simulating Bad Network Conditions

In order to simulate bad network bandwidth conditions, we use `trickle`. First, install the package:
```bash
sudo apt-get update
sudo apt-get install trickle
```

Then, run above commands to simulate bad network conditions:
```bash
trickle -s -d <DOWNLOAD_SPEED> -u <UPLOAD_SPEED> ./main <ROLE_PROGRAM>
```

### Notes on Protobuf

First, you need to install the [protobuf compiler](https://grpc.io/docs/protoc-installation/). From there, you can run `protoc` on the `message.proto` file:

```bash
protoc -I=. --cpp_out=./messages ./message.proto
```

Compiling `protobuf.cpp` will allow you test out serializing and deserializing a message.