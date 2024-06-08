#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <chrono>
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
    const char *filenames[4] = {"nice.txt", "nicer.txt", "nicest.txt", "nicerest.txt"};

    for (auto filename: filenames) {
        // Open the file in output mode (this will create the file if it does not exist)
        int fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

        std::cout << fd << std::endl;

        char buffer[1024];

        int resp = read(fd, buffer, 1024);
        resp = write(fd, "Chris Pondoc", 8);

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
    }
    std::cout << "It took " << std::chrono::time_point_cast<std::chrono::milliseconds>(get_current_time()).time_since_epoch().count() - start_time << "ms" << std::endl;

    return 0; // Return success code
}