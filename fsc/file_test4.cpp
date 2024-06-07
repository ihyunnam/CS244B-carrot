#include <iostream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string>

int main()
{
    const char *filenames[4] = {"nice.txt", "nicer.txt", "nicest.txt", "nicerest.txt"};
    const char *directory = "nice_dir";
    
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
    char cwd[1024];
    getcwd(cwd, sizeof(cwd));
    std::cout << "Current working directory: " << cwd << std::endl;

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

    if (chdir("../") == -1)
    {
        std::cerr << "Unable to change directory to " << "../" << std::endl;
        return 1; // Return an error code
    }

    std::string filename = "nicestest.txt";
    int fd = open(filename.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

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
    
    return 0; // Return success code
}