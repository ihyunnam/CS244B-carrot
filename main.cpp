#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include "sysnames.h"

#include <sys/syscall.h>

#include <unistd.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <netdb.h>

// Code for protobufs
#include "protobufs/messages/message.pb.h"
#include "protobufs/messages/message.pb.cc"

#define PORT 12346
using namespace std;

#define NUM_INTERMEDIARIES 1
struct sockaddr_in intermediaries[NUM_INTERMEDIARIES];
const char *ip_addresses[NUM_INTERMEDIARIES] = {
    "34.41.143.79"};

bool isBufferNonEmpty(const char buffer[])
{
    for (size_t i = 0; buffer[i] != '\0'; ++i)
    {
        if (!std::isspace(buffer[i]))
        {
            return true; // Found a non-whitespace character
        }
    }
    return false; // All characters are whitespace
}

string extractHostUrl(const char *httpRequest) {
    const char *hostPrefix = "Host: ";
    const char *hostLine = strstr(httpRequest, hostPrefix);
    if (hostLine != nullptr) {
        hostLine += strlen(hostPrefix);
        const char *endOfLine = strchr(hostLine, '\n');
        if (endOfLine != nullptr) {
            string hostUrl(hostLine, endOfLine - hostLine);
            return hostUrl;
        }
    }
    return ""; // Return empty string if host URL is not found
}

string urlToIpAddress(const string &url) {
    struct addrinfo hints, *res;
    int status;
    char ipstr[INET6_ADDRSTRLEN];
    char portstr[16] = {};
    sprintf(portstr, "%d", 80);

    // memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    hints.ai_protocol = IPPROTO_TCP;

    if ((status = getaddrinfo(url.c_str(), portstr, &hints, &res)) != 0) {
        cerr << "getaddrinfo: " << gai_strerror(status) << endl;
        return "";
    }

    void *addr;
    if (res->ai_family == AF_INET) { // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        addr = &(ipv4->sin_addr);
    } else { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        addr = &(ipv6->sin6_addr);
    }

    inet_ntop(res->ai_family, addr, ipstr, sizeof ipstr);

    freeaddrinfo(res);

    return ipstr;
}

int main(int argc, char *argv[])
{
    // Set up intermediaries
    for (int i = 0; i < NUM_INTERMEDIARIES; ++i)
    {
        intermediaries[i].sin_family = AF_INET;
        intermediaries[i].sin_port = htons(PORT);
        if (inet_pton(AF_INET, ip_addresses[i], &intermediaries[i].sin_addr) <= 0)
        {
            cerr << "Invalid address: " << ip_addresses[i] << endl;
            return -1;
        }
    }

    int sockfd_send;
    struct sockaddr_in servaddr_send;

    if ((sockfd_send = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        cerr << "Socket creation failed" << endl;
        return -1;
    }

    // Filling server information
    servaddr_send.sin_family = AF_INET;
    servaddr_send.sin_addr.s_addr = INADDR_ANY;
    servaddr_send.sin_port = htons(PORT);

    // Bind to a socket
    if (bind(sockfd_send, (const struct sockaddr *)&servaddr_send, sizeof(servaddr_send)) < 0)
    {
        cerr << "Binding failed 1" << endl;
        return -1;
    }

    // Read in arguments
    if (argc == 1)
    {
        exit(0);
    }
    char *chargs[argc];
    int i = 0;
    while (i < argc - 1)
    {
        chargs[i] = argv[i + 1];
        i++;
    }

    // Fork a child process
    pid_t child_pid = fork();
    chargs[i] = NULL;

    // Error handling
    if (child_pid == -1)
    {
        fprintf(stderr, "Failed to fork");
        return 1;
    }
    else if (child_pid == 0)
    {
        // Child process
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execvp(chargs[0], chargs);
    }
    else
    {
        // Parent process
        int status;
        std::ofstream outfile("output.txt");

        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status))
        {
            printf("Child process exited normally");
            return 0;
        }

        while (true)
        {
            ptrace(PTRACE_SYSCALL, child_pid, nullptr, nullptr);
            waitpid(child_pid, &status, 0);
            if (WIFEXITED(status))
            {
                break;
            }

            // Check if syscall was made
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
            long syscall_num = regs.orig_rax;

            if (syscall_num == SYS_sendto)
            {
                // Read in and check buffer
                char buffer[1024];
                for (int i = 0; i < 1024; i += 1)
                {
                    buffer[i] = ptrace(PTRACE_PEEKDATA, child_pid, regs.rsi + i, 0);
                    if (buffer[i] == '\0')
                    {
                        cout << i << endl;
                        break;
                    }
                }
                string url = extractHostUrl(buffer);
                string ip = urlToIpAddress(url);

                // fprintf(stderr, "buffer %s\n", extractHostUrl(buffer));
                cout << url << endl;
                cout << ip << endl;

                // Read in and check destination address information
                if (isBufferNonEmpty(buffer) and strlen(buffer) > 10)
                {
                    struct sockaddr_in dest_addr;
                    for (long unsigned int i = 0; i < sizeof(struct sockaddr_in); i += 1)
                    {
                        *((char *)(&dest_addr) + i) = ptrace(PTRACE_PEEKDATA, child_pid, regs.r8 + i, 0);
                    }

                    dest_addr.sin_port = htons(80);
                    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

                    // Print out port and address of destination address
                    fprintf(stderr, "sin_port %d\n", ntohs(dest_addr.sin_port));
                    fprintf(stderr, "sin_addr %s\n", inet_ntoa(dest_addr.sin_addr));

                    // Create a message
                    CarrotMessage message;
                    message.set_message(buffer);
                    message.set_port(ntohs(dest_addr.sin_port));
                    message.set_ip_address(inet_ntoa(dest_addr.sin_addr));

                    // Serialize the message
                    string serialized_data;
                    message.SerializeToString(&serialized_data);
                    
                    // Send message
                    // sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[0], sizeof(intermediaries[0]));

                    // // Make child process not sendto (not working)
                    // regs.orig_rax = -1;
                    // ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                }
            }

            outfile << "system call number " << syscall_num
                    << " name " << callname(syscall_num)
                    << " from pid " << child_pid << std::endl;
        }
        outfile.close();
    }
    return 0;
}
