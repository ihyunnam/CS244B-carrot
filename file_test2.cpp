#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>

int main()
{
    const char *directory = "cool";
    const char *filename = "sample.txt";

    // Create the directory "cool" with read/write/execute permissions for the owner
    if (mkdir(directory, S_IRWXU) == -1)
    {
        std::cerr << "Unable to create directory " << directory << std::endl;
        return 1; // Return an error code
    }

    // Change the current working directory to "cool"
    if (chdir(directory) == -1)
    {
        std::cerr << "Unable to change directory to " << directory << std::endl;
        return 1; // Return an error code
    }

    // Open the file in output mode (this will create the file if it does not exist)
    int fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    // Check if the file was successfully opened
    if (fd == -1)
    {
        std::cerr << "Unable to open file " << filename << std::endl;
        return 1; // Return an error code
    }

    std::cout << "File opened successfully." << std::endl;

    // Write to the file
    const char *text = "Chris Pondoc";
    ssize_t bytes_written = write(fd, text, strlen(text));
    if (bytes_written == -1)
    {
        std::cerr << "Error writing to file " << filename << std::endl;
        close(fd);
        return 1; // Return an error code
    }

    std::cout << "Written " << bytes_written << " bytes to the file." << std::endl;

    // Close the file
    if (close(fd) == -1)
    {
        std::cerr << "Error closing file " << filename << std::endl;
        return 1; // Return an error code
    }

    std::cout << "File closed successfully." << std::endl;

    return 0; // Return success code
}
