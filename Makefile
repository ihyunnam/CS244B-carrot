# Makefile

# Compiler
CC = g++

# Compiler flags
CFLAGS = -Wall -Wextra -std=c++11

# Source files
SOURCES = fsc/file_test5.cpp fsc/file_test4.cpp fsc/file_test3.cpp fsc/file_test2.cpp fsc/file_carrot.cpp fsc/file_receiver.cpp nsc/curl.cpp nsc/networking_carrot.cpp nsc/networking_receiver.cpp

# Executable name
EXECUTABLES = $(SOURCES:.cpp=)

all: $(EXECUTABLES)

%: %.cpp
	$(CC) $(CFLAGS) $< -o $@ -lprotobuf -lcurl -lresolv -lssl -lcrypto

# $(EXECUTABLE): $(SOURCES)
# 	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

clean:
	rm -f $(EXECUTABLES)
