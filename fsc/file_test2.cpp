#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstring>
#include <chrono>

using namespace std;
/*
 * Helper utility to get the current time
 */
std::chrono::system_clock::time_point get_current_time()
{
    return std::chrono::system_clock::now();
}

int main()
{
    long start_time = std::chrono::time_point_cast<std::chrono::milliseconds>(get_current_time()).time_since_epoch().count();
    const char *directory = "nice";
    const char *filename = "awesome.txt";
    char cwd[1024];

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

    // Get and print the current working directory
    // TO-DO: Error handling!
    getcwd(cwd, sizeof(cwd));
    std::cout << "Current working directory: " << cwd << std::endl;

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
    std::cout << "It took " << std::chrono::time_point_cast<std::chrono::milliseconds>(get_current_time()).time_since_epoch().count() - start_time << "ms" << std::endl;

    return 0; // Return success code
}
