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
#include <sstream>


#include "../helpers/sysnames.h"

// Code for protobufs
#include "../protobufs/messages/message.pb.h"
#include "../protobufs/messages/message.pb.cc"

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

    

    // Receive data indefinitely
    while (true)
    {
        n = recvfrom(sockfd, buffer, MAX_BUFFER_SIZE, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
        buffer[n] = '\0';

        // Deserialize
        CarrotMessage deserialized_message;
        deserialized_message.ParseFromString(buffer);

        // Set up destination info
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;

        // Get destination information from the deserialized string
        dest_addr.sin_port = htons(deserialized_message.port());
        inet_pton(AF_INET, deserialized_message.ip_address().c_str(), &dest_addr.sin_addr);

        // Print out port and address of destination address
        fprintf(stderr, "sin_port %d\n", ntohs(dest_addr.sin_port));
        fprintf(stderr, "sin_addr %s\n", inet_ntoa(dest_addr.sin_addr));

        // Truncate the message
        size_t pos = deserialized_message.message().find("Connection: close");
        if (pos != std::string::npos) {
            // Find the position of the newline after "Connection: close"
            size_t newline_pos = deserialized_message.message().find("\r\n\n", pos);
            if (newline_pos != std::string::npos) {
                // Extract the substring up to and including the newline
                std::string truncated_request = deserialized_message.message().substr(0, newline_pos + 2);
                deserialized_message.set_message(truncated_request);
            } else {
                std::cout << "Newline after 'Connection: close' not found." << std::endl;
            }
        } else {
            std::cout << "'Connection: close' not found." << std::endl;
        }

        // Create a socket to send out the GET request
        sockfd_send = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_send < 0) {
            perror("Error creating socket");
            return 1;
        }

        // Connect to the server
        if (connect(sockfd_send, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("Error connecting to server");
            close(sockfd_send);
            return 1;
        }

        if (send(sockfd_send, deserialized_message.message().c_str(), deserialized_message.message().length(), 0) < 0) {
            perror("Error sending request");
            close(sockfd_send);
            return 1;
        }

        // Hardcode the send back for now
        struct sockaddr_in sender_addr;
        sender_addr.sin_family = AF_INET;
        sender_addr.sin_port = htons(12346);
        inet_pton(AF_INET, "34.134.91.102", &sender_addr.sin_addr);

        // Receive the response
        // Receive data in a loop
        int bytes_received;
        cout << "Receiving bytes" << endl;
        std::stringstream received_data;
        while ((bytes_received = recv(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0)) > 0) {
            buffer[bytes_received] = '\0'; // Null-terminate the received data
            received_data << buffer; // Concatenate the received data
            // cout << buffer << endl;
            // sendto(sockfd, buffer, bytes_received, 0, (const struct sockaddr *)&sender_addr, sizeof(sender_addr));
            // exit();
            // sendto()
            // int port = 12346;
            // string ip_address = "34.134.91.102";
            // std::cout << buffer; // Print the response
        }
        if (bytes_received < 0) {
            perror("Error receiving response");
        }

        // Print the concatenated data
        std::cout << "Concatenated data:" << std::endl;
        // std::cout << received_data.str() << std::endl;

        // Convert stringstream to const char*
        std::string data_str = received_data.str();
        const char* data_buffer = data_str.c_str();
        size_t data_size = data_str.size();
        cout << data_size << endl;

        // Send the concatenated data using sendto
        ssize_t bytes_sent = sendto(sockfd, data_buffer, data_size, 0, (const struct sockaddr *)&sender_addr, sizeof(sender_addr));
        if (bytes_sent < 0) {
            perror("Error sending data");
            close(sockfd);
            return 1;
        }

        
    }

    return 0;
}