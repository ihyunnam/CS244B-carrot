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
    int sockfd;
    char buffer[MAX_BUFFER_SIZE];
    struct sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        cerr << "Socket creation failed" << endl;
        return -1;
    }

    // Zero out address fields
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        cerr << "Binding failed" << endl;
        return -1;
    }

    // Specify the destination address (IP address and port)
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT); // Destination port
    inet_pton(AF_INET, "171.64.15.27", &dest_addr.sin_addr); // Destination IP address

    while (true) {
        // Get message from standard input
        cout << "Enter message: ";
        cin.getline(buffer, MAX_BUFFER_SIZE);

        // Sending data to the specific IP address
        printf("buffer address: %llx dest_addr %llx \n", (long long int) buffer, (long long int) &dest_addr);
        sendto(sockfd, buffer, strlen(buffer), 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr));
    }

    return 0;
}
