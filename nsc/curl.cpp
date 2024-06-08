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
#include <chrono>

#define PORT 12337
#define MAX_BUFFER_SIZE 100000
using namespace std;

/*
 * Helper utility to get the current time
 */
std::chrono::system_clock::time_point get_current_time()
{
    return std::chrono::system_clock::now();
}

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        std::cerr << "Usage: " << argv[0] << " <URL>\n";
        return 1;
    }

    long start_time = std::chrono::time_point_cast<std::chrono::milliseconds>(get_current_time()).time_since_epoch().count();

    sockaddr_in servaddr;
    memset(&servaddr, 0, sizeof(servaddr));

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

    // Filling server information
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = INADDR_ANY;
    servaddr.sin_port = htons(PORT); // Set the port number here

    // Bind the socket with the server address
    if (bind(sockfd, reinterpret_cast<const sockaddr *>(&servaddr), sizeof(servaddr)) < 0)
    {
        std::cerr << "Binding failed" << std::endl;
        close(sockfd);
        return -1;
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
    cout << "receiving bytes" << endl;
    if ((bytes_received = recv(sockfd, buffer, MAX_BUFFER_SIZE - 1, 0)) > 0)
    {
        cout << bytes_received << endl;
        buffer[bytes_received] = '\0'; // Null-terminate the received data
        std::cout << buffer << endl;           // Print the response
    }
    if (bytes_received < 0)
    {
        perror("Error receiving response");
    }

    cout << "It took " << std::chrono::time_point_cast<std::chrono::milliseconds>(get_current_time()).time_since_epoch().count() - start_time << "ms" << endl;

    // Close the socket
    close(sockfd);

    return 0;
}