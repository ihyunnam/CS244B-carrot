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
#include <filesystem>
#include <cstring>
#include <netdb.h>
#include <cerrno>
#include <algorithm>
#include <fcntl.h>
#include <vector>
#include <regex>

// Hashing Libs
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <sstream>
#include <iomanip>
#include <map>

/* BEGIN HASH UTIL */

// Helper function to compute SHA-256 hash
std::string sha256(const std::string &input) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if(mdctx == NULL) {
        throw std::runtime_error("EVP_MD_CTX_new failed");
    }

    if(1 != EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestInit_ex failed");
    }

    if(1 != EVP_DigestUpdate(mdctx, input.c_str(), input.size())) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestUpdate failed");
    }

    if(1 != EVP_DigestFinal_ex(mdctx, hash, NULL)) {
        EVP_MD_CTX_free(mdctx);
        throw std::runtime_error("EVP_DigestFinal_ex failed");
    }

    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

class ConsistentHashing {
private:
    std::map<std::string, std::string> ring;

public:
    void addNode(const std::string &node) {
        std::string hash = sha256(node);
        ring[hash] = node;
    }

    void removeNode(const std::string &node) {
        std::string hash = sha256(node);
        ring.erase(hash);
    }

    std::string getNode(const std::string &key) {
        /* Gets exact node */
        if (ring.empty()) return "";

        std::string hash = sha256(key);
        auto it = ring.lower_bound(hash);
        if (it == ring.end()) {
            it = ring.begin();
        }
        return it->second;
    }

    std::vector<std::string> getClosestNodes(const std::string &key) {
        std::vector<std::string> closestNodes;
        if (ring.empty()) return closestNodes;

        std::string hash = sha256(key);
        auto it = ring.lower_bound(hash);

        if (it == ring.end()) {
            it = ring.begin();
        }

        // Currently getting 2 closest nodes
        for (int i = 0; i < 1; ++i) {
            closestNodes.push_back(it->second);
            ++it;
            if (it == ring.end()) {
                it = ring.begin();
            }
        }

        return closestNodes;
    }

    void printRing() {
        for (const auto &pair : ring) {
            std::cout << pair.first << " -> " << pair.second << std::endl;
        }
    }
};

/* END HASH UTIL */

std::string files[] = {
    "/etc/ld.so.cache",
    "/lib/x86_64-linux-gnu/libstdc++.so.6",
    "/lib/x86_64-linux-gnu/libgcc_s.so.1",
    "/lib/x86_64-linux-gnu/libc.so.6",
    "/lib/x86_64-linux-gnu/libm.so.6"};

// Code for protobufs
#include "../protobufs/files/file.pb.h"
#include "../protobufs/files/file.pb.cc"

#define PORT 12346
#define MAX_BUFFER_SIZE 5012
using namespace std;

#define NUM_INTERMEDIARIES 2
struct sockaddr_in intermediaries[NUM_INTERMEDIARIES];
const char *ip_addresses[NUM_INTERMEDIARIES] = {
    "34.134.91.102", 
    // "34.41.143.79",
    "35.185.229.10"
};


int findIpIndex(const char* target) {
    for (int i = 0; i < NUM_INTERMEDIARIES; ++i) {
        if (strcmp(ip_addresses[i], target) == 0) {
            return i;  // Found the target string at index i
        }
    }
    return -1;  // Target string not found
}

std::string shortenPath(const std::string& filePath) {
    // Define the regex pattern
    std::regex pattern(R"(/CS244B-carrot/data(.*))");
    std::smatch matches;

    // Apply the regex pattern to the file path
    if (std::regex_search(filePath, matches, pattern)) {
        if (matches.size() == 2) {
            std::string relativePath = "." + matches.str(1);
            return relativePath + "/";
        }
    }

    return filePath; // Return the original path if regex doesn't match
}

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
    // cout << url.c_str() << endl;
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
    ConsistentHashing ch;
    string absolutePath = "./";
    map<int, string> fdToAbsolutePath;
    map<int, vector<tuple<string, int>>> localFdToRemoteFd;

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

        // Add to hash table
        ch.addNode(ip_addresses[i]);
    }

    ch.printRing();

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
            char buffer[MAX_BUFFER_SIZE];

            if (syscall_num == SYS_open || syscall_num == SYS_openat)
            {
                // Find file name
                unsigned long filename_addr = regs.rsi; // rsi contains the second argument (filename) for openat, rdi for openat
                std::string filename = readStringFromProcess(child_pid, filename_addr);
                string abs_filename = absolutePath + filename;
                // std::cout << "Open syscall called with file: " << filename << std::endl;

                // Check if file is something that isn't usually opened
                bool found = find(begin(files), std::end(files), filename) != std::end(files);
                if (!found)
                {
                    // Find flags and mode
                    unsigned long dirfd = regs.rdi; // rdi contains the first argument (dirfd)
                    unsigned long flags = regs.rdx; // rdx contains the third argument (flags)
                    unsigned long mode = regs.r10;  // r10 contains the fourth argument (mode)

                    vector<string> node_ips = ch.getClosestNodes(abs_filename);
                    bool has_set = false;
                    vector<tuple<string, int>> remote_info;

                    for (string node_ip: node_ips) {
                        int ip_index = findIpIndex(node_ip.c_str());
                        // cout << "Opening file " << abs_filename << " at machine with IP " << node_ip << endl;

                        // Serialize
                        CarrotFileRequest request;
                        request.set_syscall_num(syscall_num);
                        request.set_buffer(filename);
                        request.set_arg_three(flags);
                        request.set_arg_four(mode);

                        string serialized_data;
                        request.SerializeToString(&serialized_data);

                        // Send to another machine
                        sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[ip_index], sizeof(intermediaries[ip_index]));
                        // cout << "Sending message" << endl;

                        // Receive message
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
                            if (has_set == false) {
                                regs.rax = response.return_val();
                                regs.orig_rax = -1;
                                has_set = true;
                                fdToAbsolutePath[response.return_val()] = abs_filename;
                            }
                            remote_info.push_back({ip_addresses[ip_index], response.return_val()});
                        }
                    }
                    localFdToRemoteFd[regs.rax] = remote_info;
                    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                }
            }

            // Close the file
            else if (syscall_num == SYS_close)
            {
                unsigned long fd = regs.rdi; // rdi contains the first argument (dirfd)

                // string node_ip = ch.getNode(fdToAbsolutePath[fd]);
                vector<string> node_ips = ch.getClosestNodes(fdToAbsolutePath[fd]);

                for (string node_ip: node_ips) {
                    // cout << "Closing file " << fdToAbsolutePath[fd] << " at machine with IP " << node_ip << endl;
                    int ip_index = findIpIndex(node_ip.c_str());

                    // Serialize
                    CarrotFileRequest request;
                    request.set_syscall_num(syscall_num);
                    request.set_arg_one(fd);

                    string serialized_data;
                    request.SerializeToString(&serialized_data);

                    // Send to another machine
                    sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[ip_index], sizeof(intermediaries[ip_index]));

                    // Receive message
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
                }
                localFdToRemoteFd.erase(fd);
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            // Read from file
            else if (syscall_num == SYS_read)
            {
                unsigned long fd = regs.rdi;          // rdi contains the first argument (fd)
                unsigned long buffer_addr = regs.rsi; // rsi contains the second argument (buf)
                unsigned long count = regs.rdx;       // rdx contains the third argument (count)

                string node_ip = ch.getNode(fdToAbsolutePath[fd]);
                // cout << "Reading file " << fdToAbsolutePath[fd] << " at machine with IP " << node_ip << endl;
                int ip_index = findIpIndex(node_ip.c_str());

                // Serialize
                CarrotFileRequest request;
                request.set_syscall_num(syscall_num);
                request.set_arg_one(fd);
                request.set_arg_three(count);

                string serialized_data;
                request.SerializeToString(&serialized_data);

                // Send to another machine
                sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[ip_index], sizeof(intermediaries[ip_index]));

                // Receive message
                socklen_t len;
                len = sizeof(cliaddr); // len is value/result
                int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                buffer[n] = '\0';

                CarrotFileResponse response;
                serialized_data = buffer;
                response.ParseFromString(serialized_data);
                const char *response_buf = response.buffer().c_str();

                // Change return value
                if (response.return_val() != -1)
                {
                    regs.rax = response.return_val();

                    write_memory(child_pid, regs.rsi, (void *)response_buf, response.return_val());

                    regs.orig_rax = -1;
                }
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            // Write from file
            else if (syscall_num == SYS_write)
            {
                unsigned long fd = regs.rdi;          // rdi contains the first argument (fd)
                unsigned long buffer_addr = regs.rsi; // rsi contains the first argument (buf)
                unsigned long count = regs.rdx;       // rdx contains the third argument (count)
                
                vector<string> node_ips = ch.getClosestNodes(fdToAbsolutePath[fd]);

                read_memory(child_pid, buffer_addr, buffer, count);

                std::string data = buffer;

                for (string node_ip: node_ips) {
                    // cout << "Writing to file " << fdToAbsolutePath[fd] << " at machine with IP " << node_ip << endl;
                    int ip_index = findIpIndex(node_ip.c_str());
                    
                    // Serialize
                    CarrotFileRequest request;
                    request.set_syscall_num(syscall_num);
                    request.set_arg_one(fd);
                    request.set_buffer(data);
                    request.set_arg_three(count);

                    string serialized_data;
                    request.SerializeToString(&serialized_data);

                    // Send to another machine
                    sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[ip_index], sizeof(intermediaries[ip_index]));

                    // Receive message
                    socklen_t len;
                    len = sizeof(cliaddr); // len is value/result
                    int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                    buffer[n] = '\0';

                    CarrotFileResponse response;
                    serialized_data = buffer;
                    response.ParseFromString(serialized_data);
                    const char *response_buf = response.buffer().c_str();

                    // Change return value
                    if (response.return_val() != -1)
                    {
                        regs.rax = response.return_val();
                        regs.orig_rax = -1;
                    }
                }
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            else if (syscall_num == SYS_chdir)
            {
                // Trace out the buffer
                unsigned long buffer_addr = regs.rdi;
                read_memory(child_pid, buffer_addr, buffer, MAX_BUFFER_SIZE);
                absolutePath += buffer;
                string data = buffer;

                for (int i = 0; i < NUM_INTERMEDIARIES; i++) {
                    // Serialize
                    CarrotFileRequest request;
                    request.set_syscall_num(syscall_num);
                    request.set_buffer(data);

                    string serialized_data;
                    request.SerializeToString(&serialized_data);

                    // Send to another machine
                    sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[i], sizeof(intermediaries[i]));

                    // Receive message
                    socklen_t len;
                    len = sizeof(cliaddr); // len is value/result
                    int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                    buffer[n] = '\0';

                    CarrotFileResponse response;
                    serialized_data = buffer;
                    response.ParseFromString(serialized_data);

                    // Change return value
                    response.buffer();

                    if (response.return_val() != -1)
                    {
                        regs.rax = response.return_val();
                        regs.orig_rax = -1;

                        absolutePath = shortenPath(response.buffer());
                    }
                }
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            else if (syscall_num == SYS_mkdir)
            {
                // Trace out the buffer and mode
                unsigned long buffer_addr = regs.rdi;
                unsigned long mode = regs.rsi;
                read_memory(child_pid, buffer_addr, buffer, MAX_BUFFER_SIZE);
                string data = buffer;

                for (int i = 0; i < NUM_INTERMEDIARIES; i++) {
                    // Serialize
                    // cout << "Making dir with data: " << data << endl;

                    CarrotFileRequest request;
                    request.set_syscall_num(syscall_num);
                    request.set_buffer(data);
                    request.set_arg_two(mode);

                    string serialized_data;
                    request.SerializeToString(&serialized_data);

                    // Send to another machine
                    sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[i], sizeof(intermediaries[i]));

                    // Receive message
                    socklen_t len;
                    len = sizeof(cliaddr); // len is value/result
                    int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                    buffer[n] = '\0';

                    CarrotFileResponse response;
                    serialized_data = buffer;
                    // cout << "THIS IS BUFFER: " << buffer << endl;
                    response.ParseFromString(serialized_data);

                    // Change return value
                    if (response.return_val() != -1)
                    {
                        regs.rax = response.return_val();
                        regs.orig_rax = -1;
                    }
                }
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            else if (syscall_num == SYS_getcwd)
            {
                // Trace out size
                unsigned long size = regs.rsi;

                // Serialize
                CarrotFileRequest request;
                request.set_syscall_num(syscall_num);
                request.set_arg_two(size);

                string serialized_data;
                request.SerializeToString(&serialized_data);

                // Send to another machine
                sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[0], sizeof(intermediaries[0]));

                // Receive message
                socklen_t len;
                len = sizeof(cliaddr); // len is value/result
                int n = recvfrom(sockfd_send, buffer, MAX_BUFFER_SIZE - 1, 0, reinterpret_cast<sockaddr *>(&cliaddr), &len);
                buffer[n] = '\0';

                // Deserialize the message
                CarrotFileResponse response;
                serialized_data = buffer;
                response.ParseFromString(serialized_data);
                string shorten = shortenPath(response.buffer());
                const char *response_buf = shorten.c_str();
                // cout << shorten << endl;

                // Fill in buffer
                // TO-DO: RETURN VALUE
                regs.rax = reinterpret_cast<uint64_t>(response_buf);
                regs.orig_rax = -1;
                write_memory(child_pid, regs.rdi, (void *)response_buf, response.buffer().length());
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            outfile << "system call number " << syscall_num
                    << " name " << callname(syscall_num)
                    << " from pid " << child_pid << std::endl;
        }
        outfile.close();
    }
    return 0;
}

