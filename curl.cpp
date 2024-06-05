/*
 * This code's function is simply to make HTTP GET requests to websites (no SSL).
 */
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>

#define MAX_BUFFER_SIZE 1024
using namespace std;

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <URL>\n";
        return 1;
    }

    // Parse the URL to extract the host and path
    std::string url(argv[1]);
    std::string host, path;
    size_t host_start = url.find("://");
    if (host_start != std::string::npos)
    {
        host_start += 3; // skip "://"
        size_t path_start = url.find("/", host_start);
        if (path_start == std::string::npos)
        {
            host = url.substr(host_start);
            path = "/";
        }
        else
        {
            host = url.substr(host_start, path_start - host_start);
            path = url.substr(path_start);
        }
    }
    else
    {
        std::cerr << "Invalid URL format\n";
        return 1;
    }

    // Create a TCP socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        perror("Error creating socket");
        return 1;
    }

    // Resolve the host
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host.c_str(), "http", &hints, &res) != 0)
    {
        perror("Error resolving host");
        close(sockfd);
        return 1;
    }

    // Connect to the server
    if (connect(sockfd, res->ai_addr, res->ai_addrlen) < 0)
    {
        perror("Error connecting to server");
        close(sockfd);
        freeaddrinfo(res);
        return 1;
    }

    freeaddrinfo(res);

    // HTTP GET request
    std::string http_request = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";

    // Send the request
    if (send(sockfd, http_request.c_str(), http_request.length(), 0) < 0)
    {
        perror("Error sending request");
        close(sockfd);
        return 1;
    }

    // Receive the response
    char buffer[MAX_BUFFER_SIZE];
    int bytes_received;
    cout << "Thought to receive" << endl;
    while ((bytes_received = recv(sockfd, buffer, MAX_BUFFER_SIZE - 1, 0)) > 0)
    {
        cout << "Hey there" << endl;
        buffer[bytes_received] = '\0'; // Null-terminate the received data
        std::cout << buffer;           // Print the response
    }
    if (bytes_received < 0)
    {
        perror("Error receiving response");
    }

    // Close the socket
    close(sockfd);

    return 0;
}