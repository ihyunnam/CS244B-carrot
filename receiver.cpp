#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

// Code for protobufs
#include "protobufs/messages/message.pb.h"
#include "protobufs/messages/message.pb.cc"

#define PORT 12346 // Change the port number here
#define MAX_BUFFER_SIZE 1024
using namespace std;

int main() {
    int sockfd;
    char buffer[MAX_BUFFER_SIZE];
    sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
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
    if (bind(sockfd, reinterpret_cast<const sockaddr*>(&servaddr), sizeof(servaddr)) < 0) {
        std::cerr << "Binding failed" << std::endl;
        return -1;
    }

    int n;
    socklen_t len;
    len = sizeof(cliaddr);  // len is value/result

    // Receive data indefinitely
    while (true) {
        n = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, reinterpret_cast<sockaddr*>(&cliaddr), &len);
        buffer[n] = '\0';

        // Deserialize message
        CarrotMessage deserialized_message;
        string serialized_data = buffer;
        deserialized_message.ParseFromString(serialized_data);

        // Print message data
        cout << "Message: " << deserialized_message.message() << endl;
        cout << "To Address: " << deserialized_message.ip_address().c_str() << endl;
        cout << "To Port: " <<  htons(deserialized_message.port()) << endl;

        // Set up destination info
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;

        // Get destination information from the deserialized string
        dest_addr.sin_port = htons(deserialized_message.port());
        inet_pton(AF_INET, deserialized_message.ip_address().c_str(), &dest_addr.sin_addr);

        // Perform same sendto
        // sendto()
        n = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, reinterpret_cast<sockaddr*>(&cliaddr), &len);
        buffer[n] = '\0';
    }

    return 0;
}
