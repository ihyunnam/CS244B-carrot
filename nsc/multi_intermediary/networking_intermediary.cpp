#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <random>

// Code for protobufs
#include "protobufs/messages/message.pb.h"
#include "protobufs/messages/message.pb.cc"

#define PORT 12346 // Change the port number here
#define MAX_BUFFER_SIZE 1024
using namespace std;

string SAVED_FOLDER = "data/";

/* This is the code for an intermediary that forwards a GET request to another machine
   that's closer to the destination. This code selects the next machine at random and
   does not accurately simulate the process of finding a machine that's closer
   to the destination, like in a real network hopping.

   A machine forwards the request to the final destination, as opposed to another machine,
   if its randomly generated number DISTANCE_TO_DESTINATION is less than 0.3.

   Each machine replaces the sender address in the packet sent to the next machine
   with its own IP so that when the GET request is fulfilled, the receiver (destination)
   and all intermediary machines can send the response back to the sender in reverse order.
*/

// List of intermediary IP addresses
const char *intermediary_ips[NUM_INTERMEDIARIES] = {
    "192.168.1.2",
    "192.168.1.3",
    "192.168.1.4"
};
// TODO: change with real IPs

const char *get_next_ip(const char* my_ip) {
    std::mt19937 generator(std::random_device{}());
    std::uniform_int_distribution<std::size_t> distribution(0, NUM_INTERMEDIARIES - 1);

    bool found = false;
    std::size_t number = 0;
    // Repeat until IP that's not myself is chosen
    while (!found) {
        number = distribution(generator);
        if (intermediary_ips[number] != my_ip) {
            found = true;
        }
    }
    return intermediary_ips[number];
}

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

    // Extract my own IP from servaddr
    char my_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(servaddr.sin_addr), my_ip, INET_ADDRSTRLEN);

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

        // Append own IP address to sender address array
        deserialized_message.add_sender_addr(my_ip);

        // If distance < 0.3, forward to destination. Else, (not yet inside firewall) forward to another intermediary.
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_real_distribution<> dis(0, 1);
        double distance = dis(gen);
        
        // Set up destination info
        struct sockaddr_in dest_addr;
        dest_addr.sin_family = AF_INET;
        if (distance < 0.3) { // forward directly to destination
            dest_addr.sin_port = htons(deserialized_message.port());
        } else { // forward to another intermediary
            const char* next_ip_str = get_next_ip(own_ip);
            struct in_addr next_ip;
            inet_pton(AF_INET, ip_str, &next_ip)
            dest_addr = next_ip;
        }
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

        struct sockaddr_in sender_addr;
        sender_addr.sin_family = AF_INET;
        sender_addr.sin_port = htons(12346); // TODO: fix? But we don't seem to use it later.
        // Retrieve previous intermediary that forwarded message to current
        const char* prev_ip = deserialized_message.pop_sender_addr();
        inet_pton(AF_INET, prev_ip.c_str(), &sender_addr.sin_addr);

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
