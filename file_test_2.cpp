#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>

using namespace std;

int main()
{
    const char *filename = "read.txt";
    const size_t bufferSize = 1024;
    char buffer[bufferSize];

    // Open the file in read-only mode
    int fd = open(filename, O_RDONLY);

    // Check if the file was successfully opened
    if (fd == -1)
    {
        std::cerr << "Unable to open file " << filename << std::endl;
        return 1; // Return an error code
    }

    std::cout << "File opened successfully." << std::endl;

    // Read the file contents and print them to the console
    ssize_t bytesRead;
    while ((bytesRead = read(fd, buffer, bufferSize - 1)) > 0)
    {
        buffer[bytesRead] = '\0'; // Null-terminate the buffer
        cout << buffer;
    }

    if (bytesRead == -1)
    {
        std::cerr << "Error reading from file " << filename << std::endl;
        close(fd);
        return 1; // Return an error code
    }

    std::cout << std::endl;

    // Close the file
    if (close(fd) == -1)
    {
        std::cerr << "Error closing file " << filename << std::endl;
        return 1; // Return an error code
    }

    std::cout << "File closed successfully." << std::endl;

    return 0; // Return success code
}
