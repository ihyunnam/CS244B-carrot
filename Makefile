# Makefile

# Compiler
CC = g++

# Compiler flags
CFLAGS = -Wall -Wextra -std=c++11

# Source files
# SOURCES = intermediary.cpp receiver.cpp sender.cpp main.cpp get_website.cpp
SOURCES = file_carrot.cpp file_test_1.cpp file_test_2.cpp
# Executable name
EXECUTABLES = $(SOURCES:.cpp=)

all: $(EXECUTABLES)

%: %.cpp
	$(CC) $(CFLAGS) $< -o $@ -lprotobuf -lcurl -lresolv -lssl -lcrypto

# $(EXECUTABLE): $(SOURCES)
# 	$(CC) $(CFLAGS) $(SOURCES) -o $(EXECUTABLE)

clean:
	rm -f $(EXECUTABLES)
