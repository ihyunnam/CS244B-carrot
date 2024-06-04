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

#include "sysnames.h"

// Code for protobufs
#include "protobufs/files/file.pb.h"
#include "protobufs/files/file.pb.cc"

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

    SSL_library_init();

    // Receive data indefinitely
    while (true)
    {
        n = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
        buffer[n] = '\0';

        // Trace sender address and port
        fprintf(stderr, "Received Message from Address: %s\n", inet_ntoa(cliaddr.sin_addr));
        fprintf(stderr, "Received Message from Port: %d\n", ntohs(cliaddr.sin_port));

        // Deserialize
        CarrotFile r_file;
        r_file.ParseFromString(buffer);

        // Check system call and save!
        if (r_file.syscall_num() == SYS_openat) {
            cout << "Saved?" << endl;
            int fd = open((SAVED_FOLDER + r_file.pathname()).c_str(), r_file.flags(), r_file.mode());
            cout << "Test?" << endl;
        }

        // cout << "Pathname: " << deserialized_message.pathname() << endl;
        // cout << "Port Number: " << deserialized_message.port() << endl;
        // cout << "Message: " << deserialized_message.message() << endl;
    }

    return 0;
}
