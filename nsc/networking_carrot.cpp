#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include "../helpers/sysnames.h"
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
#include <fcntl.h>

std::string files[] = {
    "/etc/ld.so.cache",
    "/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6"};

// Code for protobufs
#include "../protobufs/messages/message.pb.h"
#include "../protobufs/messages/message.pb.cc"

#define PORT 12346
#define MAX_BUFFER_SIZE 100000
bool received = false;
using namespace std;

/* This code assumes that the sender knows and can directly send requests to
   multiple machines inside the firewall that can access the requested website.
   The sender uses the resource that arrives first.
*/

void print_time()
{
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::cout << std::ctime(&now_c);
}

/*
 * Helper utility to get the current time
 */
system_clock::time_point get_current_time()
{
    return std::chrono::system_clock::now();
}

#define NUM_INTERMEDIARIES 1
struct sockaddr_in intermediaries[NUM_INTERMEDIARIES];
const char *ip_addresses[NUM_INTERMEDIARIES] = {
    "34.82.207.241",
    "34.41.143.79"};
// TODO: replace these with real IPs

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

// Function to write memory to /proc/[pid]/mem
ssize_t write_memory(pid_t pid, unsigned long addr, void *vptr, size_t len)
{
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int fd = open(mem_path, O_WRONLY);
    if (fd == -1)
    {
        perror("open");
        return -1;
    }

    if (lseek(fd, addr, SEEK_SET) == -1)
    {
        perror("lseek");
        close(fd);
        return -1;
    }

    ssize_t n = write(fd, vptr, len);
    if (n == -1)
    {
        perror("write");
    }

    close(fd);
    return n;
}

// Function to read memory from /proc/[pid]/mem
ssize_t read_memory(pid_t pid, unsigned long addr, void *vptr, size_t len)
{
    char mem_path[256];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);

    int fd = open(mem_path, O_RDONLY);
    if (fd == -1)
    {
        perror("open");
        return -1;
    }

    if (lseek(fd, addr, SEEK_SET) == -1)
    {
        perror("lseek");
        close(fd);
        return -1;
    }

    ssize_t n = read(fd, vptr, len);
    if (n == -1)
    {
        perror("read");
    }

    close(fd);
    return n;
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

    int counter = 0;

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
            char buffer[MAX_BUFFER_SIZE];

            // Handle sends
            if (syscall_num == SYS_sendto)
            {
                // Extract the correct registers and read the buffer
                unsigned long buffer_addr = regs.rsi;
                unsigned long count = regs.rdx;
                read_memory(child_pid, buffer_addr, buffer, count);

                // Check if "GET" is in the buffer (no interposition on getaddrinfo?)
                if (strstr(buffer, "GET") != nullptr)
                {
                    // Extract URL and IP Address
                    string url = extractHostUrl(buffer);
                    string ip = urlToIpAddress(url);

                    // Obtain destination address
                    struct sockaddr_in dest_addr;
                    for (long unsigned int i = 0; i < sizeof(struct sockaddr_in); i += 1)
                    {
                        *((char *)(&dest_addr) + i) = ptrace(PTRACE_PEEKDATA, child_pid, regs.r8 + i, 0);
                    }

                    // Set destination port
                    dest_addr.sin_port = htons(80);
                    inet_pton(AF_INET, ip.c_str(), &dest_addr.sin_addr);

                    // Print out port and address of destination address
                    fprintf(stderr, "sin_port %d\n", ntohs(dest_addr.sin_port));
                    fprintf(stderr, "sin_addr %s\n", inet_ntoa(dest_addr.sin_addr));

                    // Serialize
                    CarrotMessage request;
                    request.set_ip_address(ip.c_str());
                    request.set_port(80);
                    request.set_message(buffer);

                    string serialized_data;
                    request.SerializeToString(&serialized_data);
                    auto start_time = get_current_time();
                    // Send to all intermediaries in a loop
                    for (int i = 0; i < NUM_INTERMEDIARIES; i++) {
                        sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[i], sizeof(intermediaries[i]));
                    }

                    // Reset the process
                    regs.orig_rax = SYS_getpid;
                    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                    counter += 1;
                }

                // Else, maybe we interpose here?
                else
                {
                    std::cout << "The word 'GET' is not in the buffer.\n";
                }
            }

            else if (syscall_num == SYS_recvfrom && !received)
            {
                received = true;
                cout << counter << endl;
                if (counter > 0)
                {
                    auto end_time = get_current_time();
                    duration<double> time_diff = end_time - start_time;
                    cout << "End to end time: " << time_diff.count() << " seconds" << endl;
                    // Update the counter and receive the message
                    counter -= 1;
                    socklen_t len;
                    len = sizeof(cliaddr); // len is value/result
                    ssize_t n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                    buffer[n] = '\0';

                    cout << "Size from interposition: " << n << endl;

                    // Set appropriate values
                    regs.rax = n;
                    regs.orig_rax = -1;

                    for (int i = 0; i < n; i += sizeof(long))
                    {
                        long data;
                        memcpy(&data, buffer + i, sizeof(long));
                        ptrace(PTRACE_POKEDATA, child_pid, regs.rsi + i, data);
                    }

                    // write_memory(child_pid, regs.rsi, (void *)buffer, strlen(buffer));
                    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

                    // Close socket after receiving first message
                    close(sockfd_send);
                }
                else
                {
                    cout << "Nuull call?" << endl;
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
