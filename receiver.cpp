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

// Code for protobufs
#include "protobufs/messages/message.pb.h"
#include "protobufs/messages/message.pb.cc"

#define PORT 12346 // Change the port number here
#define MAX_BUFFER_SIZE 1024
using namespace std;

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

        // Deserialize message
        CarrotMessage deserialized_message;
        string serialized_data = buffer;
        deserialized_message.ParseFromString(serialized_data);

        // Print message data
        cout << "Message: " << deserialized_message.message() << endl;
        cout << "To Address: " << deserialized_message.ip_address().c_str() << endl;
        cout << "To Port: " << deserialized_message.port() << endl;

        server = gethostbyname(deserialized_message.message().c_str());

        // Set up destination info
        struct sockaddr_in dest_addr;

        bzero((char *)&dest_addr, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(443);
        bcopy((char *)server->h_addr, (char *)&dest_addr.sin_addr.s_addr, server->h_length);

        sockfd_send = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_send < 0)
        {
            cout << "Failed to create socket" << endl;
            return 1;
        }
        SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_client_method());
        SSL *ssl = SSL_new(ssl_ctx);

        if (connect(sockfd_send, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0)
        {
            cout << "Connection failed :(" << endl;
            close(sockfd_send);
            return 1;
        }

        SSL_set_fd(ssl, sockfd_send);
        if (SSL_connect(ssl) <= 0)
        {
            cout << "SSL connection failed :(" << endl;
            close(sockfd_send);
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);
            return 1;
        }

        string resource = "/";
        string request = "GET " + resource + "" + " HTTP/1.1\r\nHost: " + deserialized_message.message().c_str() + "\r\nConnection: close\r\n\r\n";

        cout << "Request: " << endl
             << request << endl
             << endl;

        if (SSL_write(ssl, request.c_str(), request.size()) <= 0)
        {
            cout << "Failed to send request..." << endl;
            close(sockfd_send);
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);
            return 1;
        }

        int bytes_received;
        string raw_site;
        while ((bytes_received = SSL_read(ssl, buffer, sizeof(buffer))) > 0)
        {
            raw_site.append(buffer, bytes_received);
        }

        SSL_free(ssl);
        close(sockfd_send);
        SSL_CTX_free(ssl_ctx);
        // cout << raw_site << endl;

        // TODO: Send back to main
        sendto(sockfd, raw_site.c_str(), raw_site.length(), 0, (const struct sockaddr *)&cliaddr, sizeof(cliaddr));
    }

    return 0;
}
