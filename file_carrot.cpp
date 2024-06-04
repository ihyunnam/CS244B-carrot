#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include "sysnames.h"
#include <sys/types.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <fstream>
#include <cstring>
#include <netdb.h>
#include <cerrno>
#include <algorithm>

std::string files[] = {
    "/etc/ld.so.cache",
    "/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6"};

// Code for protobufs
#include "protobufs/files/file.pb.h"
#include "protobufs/files/file.pb.cc"

#define PORT 12346
#define MAX_BUFFER_SIZE 5012
using namespace std;

#define NUM_INTERMEDIARIES 1
struct sockaddr_in intermediaries[NUM_INTERMEDIARIES];
const char *ip_addresses[NUM_INTERMEDIARIES] = {
    // "34.82.207.241"};
    "34.121.111.236"};

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

string extractHostUrl(const char *httpRequest)
{
    const char *hostPrefix = "Host: ";
    const char *hostLine = strstr(httpRequest, hostPrefix);
    if (hostLine != nullptr)
    {
        hostLine += strlen(hostPrefix);
        const char *endOfLine = strchr(hostLine, '\n');
        if (endOfLine != nullptr)
        {
            string hostUrl(hostLine, endOfLine - hostLine - 1);
            return hostUrl;
        }
    }
    return ""; // Return empty string if host URL is not found
}

string urlToIpAddress(const string &url)
{
    struct addrinfo hints, *res;
    int status;
    char ipstr[INET6_ADDRSTRLEN];

    // Initialize the hints structure
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
    hints.ai_socktype = SOCK_STREAM;

    // Perform the getaddrinfo call
    cout << url.c_str() << endl;
    if ((status = getaddrinfo(url.c_str(), NULL, &hints, &res)) != 0)
    {
        cerr << "getaddrinfo: " << gai_strerror(status) << " (Error Code: " << status << ")" << endl;
        return "";
    }

    void *addr;
    if (res->ai_family == AF_INET)
    { // IPv4
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)res->ai_addr;
        addr = &(ipv4->sin_addr);
    }
    else if (res->ai_family == AF_INET6)
    { // IPv6
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)res->ai_addr;
        addr = &(ipv6->sin6_addr);
    }
    else
    {
        freeaddrinfo(res);
        return ""; // Unknown address family
    }

    // Convert the address to a string
    inet_ntop(res->ai_family, addr, ipstr, sizeof ipstr);

    // Free the address info structure
    freeaddrinfo(res);

    return ipstr;
}

// Read string from openat
std::string readStringFromProcess(pid_t pid, unsigned long addr)
{
    std::string result;
    unsigned long data;
    char *data_ptr = reinterpret_cast<char *>(&data);

    while (true)
    {
        errno = 0;
        data = ptrace(PTRACE_PEEKDATA, pid, addr, nullptr);
        if (errno != 0)
        {
            break;
        }

        for (int i = 0; i < sizeof(data); ++i)
        {
            if (data_ptr[i] == '\0')
            {
                result.append(data_ptr, i);
                return result;
            }
        }

        result.append(data_ptr, sizeof(data));
        addr += sizeof(data);
    }
    return result;
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
    struct sockaddr_in servaddr_send, cliaddr;

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

            if (syscall_num == SYS_open || syscall_num == SYS_openat)
            {
                // Find file name
                unsigned long filename_addr = regs.rsi; // rsi contains the second argument (filename) for openat, rdi for openat
                std::string filename = readStringFromProcess(child_pid, filename_addr);
                std::cout << "Open syscall called with file: " << filename << std::endl;

                // Check if file is something that isn't usually opened
                bool found = find(begin(files), std::end(files), filename) != std::end(files);
                if (!found)
                {
                    // Find flags and mode
                    unsigned long dirfd = regs.rdi; // rdi contains the first argument (dirfd)
                    unsigned long flags = regs.rdx; // rdx contains the third argument (flags)
                    unsigned long mode = regs.r10;  // r10 contains the fourth argument (mode)

                    // Serialize
                    CarrotFileRequest request;
                    request.set_syscall_num(syscall_num);
                    request.set_buffer(filename);
                    request.set_arg_three(flags);
                    request.set_arg_four(mode);

                    string serialized_data;
                    request.SerializeToString(&serialized_data);

                    // Send to another machine
                    sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[0], sizeof(intermediaries[0]));

                    // Receive message
                    char buffer[MAX_BUFFER_SIZE];
                    socklen_t len;
                    len = sizeof(cliaddr); // len is value/result
                    int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                    buffer[n] = '\0';

                    CarrotFileResponse response;
                    serialized_data = buffer;
                    response.ParseFromString(serialized_data);

                    // Change return value
                    if (response.return_val() != -1)
                    {
                        regs.rax = response.return_val();
                        regs.orig_rax = -1;
                    }
                    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                    // regs.rax = stoi(buffer);
                    // regs.orig_rax = -1;
                    // ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                }
            }

            // Close the file
            else if (syscall_num == SYS_close)
            {
                unsigned long fd = regs.rdi; // rdi contains the first argument (dirfd)

                // Serialize
                CarrotFileRequest request;
                request.set_syscall_num(syscall_num);
                request.set_arg_one(fd);

                string serialized_data;
                request.SerializeToString(&serialized_data);

                // Send to another machine
                sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[0], sizeof(intermediaries[0]));

                // Receive message
                char buffer[MAX_BUFFER_SIZE];
                socklen_t len;
                len = sizeof(cliaddr); // len is value/result
                int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                buffer[n] = '\0';

                CarrotFileResponse response;
                serialized_data = buffer;
                response.ParseFromString(serialized_data);

                // Change return value
                if (response.return_val() != -1)
                {
                    regs.rax = response.return_val();
                    regs.orig_rax = -1;
                }
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            // Read from file
            else if (syscall_num == SYS_read) {
                unsigned long fd = regs.rdi; // rdi contains the first argument (dirfd)
                unsigned long buffer_addr = regs.rsi; // rdi contains the first argument (dirfd)
                unsigned long count = regs.rdx; // rdx contains the third argument (count)

                // Serialize
                CarrotFileRequest request;
                request.set_syscall_num(syscall_num);
                request.set_arg_one(fd);
                request.set_arg_three(count);

                string serialized_data;
                request.SerializeToString(&serialized_data);

                // Send to another machine
                sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[0], sizeof(intermediaries[0]));

                // Receive message
                char buffer[MAX_BUFFER_SIZE];
                socklen_t len;
                len = sizeof(cliaddr); // len is value/result
                int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                buffer[n] = '\0';

                CarrotFileResponse response;
                serialized_data = buffer;
                response.ParseFromString(serialized_data);
                const char* response_buf = response.buffer().c_str();

                // Change return value
                if (response.return_val() != -1)
                {
                    regs.rax = response.return_val();

                    for (int i = 0; i < response.return_val(); i += 1)
                    {
                        ptrace(PTRACE_POKEDATA, child_pid, regs.rsi + i, *(response_buf+i));
                    }
                    regs.orig_rax = -1;
                }
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            // Write from file
            else if (syscall_num == SYS_write) {
                unsigned long fd = regs.rdi; // rdi contains the first argument (dirfd)
                unsigned long buffer_addr = regs.rsi; // rdi contains the first argument (dirfd)
                unsigned long count = regs.rdx; // rdx contains the third argument (count)

                std::string data = readStringFromProcess(child_pid, buffer_addr);

                // Serialize
                CarrotFileRequest request;
                request.set_syscall_num(syscall_num);
                request.set_arg_one(fd);
                request.set_buffer(data);
                request.set_arg_three(count);

                string serialized_data;
                request.SerializeToString(&serialized_data);

                // Send to another machine
                sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[0], sizeof(intermediaries[0]));

                // Receive message
                char buffer[MAX_BUFFER_SIZE];
                socklen_t len;
                len = sizeof(cliaddr); // len is value/result
                int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                buffer[n] = '\0';

                CarrotFileResponse response;
                serialized_data = buffer;
                response.ParseFromString(serialized_data);
                const char* response_buf = response.buffer().c_str();

                // Change return value
                if (response.return_val() != -1)
                {
                    regs.rax = response.return_val();
                    regs.orig_rax = -1;
                }
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }
            

            cout << "system call number " << syscall_num
                 << " name " << callname(syscall_num)
                 << " from pid " << child_pid << std::endl;
        }
        outfile.close();
    }
    return 0;
}
