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
    char cwd[1024];

    for (int i = 0; i < 10; i++) {
        if (mkdir(directory, S_IRWXU) == -1)
        {
            std::cerr << "Unable to create directory " << directory << std::endl;
            return 1; // Return an error code
        }

        if (chdir(directory) == -1)
        {
            std::cerr << "Unable to change directory to " << directory << std::endl;
            return 1; // Return an error code
        }
    }

    std::cout << "It took " << std::chrono::time_point_cast<std::chrono::milliseconds>(get_current_time()).time_since_epoch().count() - start_time << "ms" << std::endl;

    return 0; // Return success code
}
