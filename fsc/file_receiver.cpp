#include <iostream>
#include <cstring>
#include <string>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "../helpers/sysnames.h"

// Code for protobufs
#include "../protobufs/files/file.pb.h"
#include "../protobufs/files/file.pb.cc"

#define PORT 12346 // Change the port number here
#define MAX_BUFFER_SIZE 1024
using namespace std;

string SAVED_FOLDER = "data/";

int main()
{
    int sockfd, sockfd_send;
    char buffer[MAX_BUFFER_SIZE];
    sockaddr_in servaddr, cliaddr;
    struct hostent *server;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        std::cerr << "Socket creation failed" << std::endl;
        return -1;
    }

    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT); // Set the port number here

    // Bind the socket with the server address
    if (bind(sockfd, reinterpret_cast<const sockaddr *>(&servaddr), sizeof(servaddr)) < 0)
    {
        std::cerr << "Binding failed" << std::endl;
        return -1;
    }

    int n;
    socklen_t len;
    len = sizeof(cliaddr); // len is value/result

    // Set main directory
    char maindir[1024];
    chdir(SAVED_FOLDER.c_str());
    getcwd(maindir, sizeof(maindir));
    cout << maindir << endl;

    // Receive data indefinitely
    while (true)
    {
        n = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
        buffer[n] = '\0';

        // Trace sender address and port
        fprintf(stderr, "Received Message from Address: %s\n", inet_ntoa(cliaddr.sin_addr));
        fprintf(stderr, "Received Message from Port: %d\n", ntohs(cliaddr.sin_port));

        // Deserialize
        CarrotFileRequest r_file;
        r_file.ParseFromString(buffer);

        // Check system call and save!
        if (r_file.syscall_num() == SYS_openat)
        {
            int fd = open((r_file.buffer().c_str()), r_file.arg_three(), r_file.arg_four());

            // Write message
            CarrotFileResponse r_response;
            r_response.set_return_val(fd);

            // Serialize and send
            string serialized_data;
            r_response.SerializeToString(&serialized_data);
            sendto(sockfd, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));
        }

        // Handle closing a file
        else if (r_file.syscall_num() == SYS_close)
        {
            int result = close(r_file.arg_one());

            // Write message
            CarrotFileResponse r_response;
            r_response.set_return_val(result);

            // Serialize and send
            string serialized_data;
            r_response.SerializeToString(&serialized_data);
            sendto(sockfd, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));
        }

        // Handle reading a file
        else if (r_file.syscall_num() == SYS_read)
        {
            int result = read(r_file.arg_one(), buffer, r_file.arg_three());
            buffer[result] = '\0';
            CarrotFileResponse r_response;
            r_response.set_return_val(result);
            r_response.set_buffer(string(buffer));

            string serialized_data;
            r_response.SerializeToString(&serialized_data);
            sendto(sockfd, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));
        }

        // Handle writing a file
        else if (r_file.syscall_num() == SYS_write)
        {
            int result = write(r_file.arg_one(), r_file.buffer().c_str(), r_file.arg_three());
            CarrotFileResponse r_response;
            r_response.set_return_val(result);

            string serialized_data;
            r_response.SerializeToString(&serialized_data);
            sendto(sockfd, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));
        }

        // Handle getting the current directory
        else if (r_file.syscall_num() == SYS_getcwd)
        {
            // Get cwd
            char cwd[r_file.arg_two()];
            getcwd(cwd, r_file.arg_two());

            // Write response
            CarrotFileResponse r_response;
            r_response.set_buffer(string(cwd));

            // Serialize and send
            string serialized_data;
            r_response.SerializeToString(&serialized_data);
            sendto(sockfd, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));
        }

        // Handle creating a directory
        else if (r_file.syscall_num() == SYS_mkdir)
        {
            int result = mkdir(r_file.buffer().c_str(), r_file.arg_two());

            // Write response
            CarrotFileResponse r_response;
            r_response.set_return_val(result);

            // Serialize and send data
            string serialized_data;
            r_response.SerializeToString(&serialized_data);
            sendto(sockfd, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));
        }

        // Handle changing directory
        else if (r_file.syscall_num() == SYS_chdir)
        {
            int result = chdir((r_file.buffer().c_str()));

            // Extract the current working directory for assistance for interposition
            char cwd[1024];
            getcwd(cwd, 1024);

            // Write response
            CarrotFileResponse r_response;
            r_response.set_return_val(result);
            r_response.set_buffer(cwd);

            // Serialize and send data
            string serialized_data;
            r_response.SerializeToString(&serialized_data);
            sendto(sockfd, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));
        }
    }

    return 0;
}
