#include <iostream>
#include <fstream>
#include <cstring>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <chrono>

// Define destination here
#define SOURCE_PORT 12346
#define DEST_PORT 12345 // Change to 12346 if sending directly, without ./main
#define DEST_IP "34.41.143.79"
#define MAX_BUFFER_SIZE 1024

using namespace std;

/*
 * Helper utility to keep track of time
 */
void print_time()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::cout << std::ctime(&now_c);
}

/*
 * Take in text from standard input.
 */
void continuous_send(struct sockaddr_in dest_addr, int sockfd)
{
    // Have a storable buffer
    char buffer[MAX_BUFFER_SIZE];
    while (true)
    {
        // Get message from standard input
        cout << "Enter message: ";
        cin.getline(buffer, MAX_BUFFER_SIZE);

        // Sending data to the specific IP address
        printf("buffer address: %llx dest_addr %llx \n", (long long int)buffer, (long long int)&dest_addr);
        sendto(sockfd, buffer, strlen(buffer), 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr));
    }
}

/*
 * Instead of taking from c-input, try taking in a file
 */
int file_send(int sockfd, struct sockaddr_in dest_addr)
{
    // Open the file to be sent
    ifstream file("data/sample.txt", ios::binary);
    if (!file.is_open())
    {
        cerr << "Failed to open the file" << endl;
        close(sockfd);
        return 1;
    }

    char buffer[MAX_BUFFER_SIZE];
    while (!file.eof())
    {
        file.read(buffer, MAX_BUFFER_SIZE);
        streamsize bytes_read = file.gcount();

        if (bytes_read > 0)
        {
            ssize_t bytes_sent = sendto(sockfd, buffer, bytes_read, 0,
                                        (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if (bytes_sent < 0)
            {
                perror("Failed to send data");
                file.close();
                close(sockfd);
                return 1;
            }
        }
    }

    // Close the file and the socket
    file.close();
    close(sockfd);
    return 0;
}

int main()
{
    // Initial variables
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;

    // Creating socket file descriptor
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        cerr << "Socket creation failed" << endl;
        return -1;
    }

    // Zero out address fields
    memset(&servaddr, 0, sizeof(servaddr));
    memset(&cliaddr, 0, sizeof(cliaddr));

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(SOURCE_PORT);

    // Bind the socket with the server address
    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
    {
        cerr << "Binding failed" << endl;
        return -1;
    }

    // Specify the destination address (IP address and port)
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(DEST_PORT);            // Destination port
    inet_pton(AF_INET, DEST_IP, &dest_addr.sin_addr); // Destination IP address

    // Either continuously send or send a file
    // continuous_send(dest_addr, sockfd);
    print_time();
    file_send(sockfd, dest_addr);
    print_time();

    return 0;
}
