#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

int main()
{
    const char *filename = "data/test.txt";

    // Open the file in output mode (this will create the file if it does not exist)
    int fd = open(filename, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    // Check if the file was successfully opened
    if (fd == -1)
    {
        std::cerr << "Unable to open file " << filename << std::endl;
        return 1; // Return an error code
    }

    std::cout << "File opened successfully." << std::endl;

    // Close the file
    if (close(fd) == -1)
    {
        std::cerr << "Error closing file " << filename << std::endl;
        return 1; // Return an error code
    }

    std::cout << "File closed successfully." << std::endl;

    return 0; // Return success code
}
