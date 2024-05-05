#include <iostream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 12345
#define MAX_BUFFER_SIZE 1024

using namespace std;

int main() {
    // Initial variables
    int sockfd_send, sockfd_receive;
    char buffer[MAX_BUFFER_SIZE];
    struct sockaddr_in servaddr_send, servaddr_receive, cliaddr_receive;

    // Creating socket file descriptors
    if ((sockfd_send = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        cerr << "Socket creation failed" << endl;
        return -1;
    }

    if ((sockfd_receive = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        cerr << "Socket creation failed" << endl;
        return -1;
    }

    // Zero out address fields
    memset(&servaddr_send, 0, sizeof(servaddr_send));
    memset(&servaddr_receive, 0, sizeof(servaddr_receive));
    memset(&cliaddr_receive, 0, sizeof(cliaddr_receive));

    // Filling server information
    servaddr_send.sin_family = AF_INET;
    servaddr_send.sin_addr.s_addr = INADDR_ANY;
    servaddr_send.sin_port = htons(PORT);

    // Bind the socket with the server address
    if (bind(sockfd_send, (const struct sockaddr *)&servaddr_send, sizeof(servaddr_send)) < 0) {
        cerr << "Binding failed" << endl;
        return -1;
    }

    servaddr_receive.sin_family = AF_INET;
    servaddr_receive.sin_addr.s_addr = INADDR_ANY;
    servaddr_receive.sin_port = htons(PORT);

    // Bind the socket with the server address
    if (bind(sockfd_receive, (const struct sockaddr *)&servaddr_receive, sizeof(servaddr_receive)) < 0) {
        cerr << "Binding failed" << endl;
        return -1;
    }

    // Specify the destination address (IP address and port)
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT); // Destination port
    inet_pton(AF_INET, "171.64.15.22", &dest_addr.sin_addr); // Destination IP address (Myth 61)
    // TODO: change IP later (myth 65 for now)

    int n;
    socklen_t len;

    while (true) {
        // Get message from standard input
        n = recvfrom(sockfd_receive, buffer, MAX_BUFFER_SIZE, 0, reinterpret_cast<sockaddr*>(&cliaddr_receive), &len);
        buffer[n] = '\0';
        cout << "Received message: " << buffer << endl;

        // Sending data to the specific IP address
        sendto(sockfd_send, buffer, strnlen(buffer, MAX_BUFFER_SIZE), 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr));
    }

    return 0;
}
