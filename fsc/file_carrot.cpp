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
// #include "json.hpp"

// /* JSON UTIL FUNCTIONS */
// using json = nlohmann::json;

// class JSONFileManager {
// private:
//     std::string filename;
//     json data;

//     // Function to read a JSON file and return its content as a json object
//     void readJSONFile() {
//         std::ifstream file(filename);
//         file >> data;
//         file.close();
//     }

//     // Function to write a json object to a JSON file
//     void writeJSONFile() {
//         std::ofstream file(filename);
//         file << std::setw(4) << data << std::endl;
//         file.close();
//     }

// public:
//     JSONFileManager(const std::string& filename) : filename(filename) {
//         readJSONFile();
//     }

//     // Function to edit the contents of a specific key
//     void editKey(const std::string& key, const std::vector<std::tuple<std::string, int>>& new_values) {
//         data[key] = new_values;
//         writeJSONFile();
//     }

//     // Function to get the values associated with a specific key
//     json getKey(const std::string& key) const {
//         if (data.contains(key)) {
//             return data.at(key);
//         } else {
//             return -1;
//         }
//     }
// };

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

        // Currently getting 3 closest nodes
        for (int i = 0; i < 3; ++i) {
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

#define NUM_INTERMEDIARIES 1
struct sockaddr_in intermediaries[NUM_INTERMEDIARIES];
const char *ip_addresses[NUM_INTERMEDIARIES] = {
    // "34.82.207.241"};
    // "34.41.143.79"};
    "34.134.91.102"};


int findIpIndex(const char* target) {
    for (int i = 0; i < NUM_INTERMEDIARIES; ++i) {
        if (strcmp(ip_addresses[i], target) == 0) {
            return i;  // Found the target string at index i
        }
    }
    return -1;  // Target string not found
}

// string getAbsolutePath(const string& path) {
//     try {
//         return filesystem::absolute(path).string();
//     } catch (const filesystem::filesystem_error& e) {
//         throw runtime_error(e.what());
//     }
// }

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
    ConsistentHashing ch;
    string absolutePath = "./";
    map<int, string> fdToAbsolutePath;
    map<int, vector<tuple<string, int>>> localFdToRemoteFd;
    // JSONFileManager jsonManager("fd_info.json");
    // JSONFileManager pathToFd("path_fd_map.json");

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
                std::cout << "Open syscall called with file: " << filename << std::endl;

                // Check if file is something that isn't usually opened
                bool found = find(begin(files), std::end(files), filename) != std::end(files);
                if (!found)
                {
                    // Find flags and mode
                    unsigned long dirfd = regs.rdi; // rdi contains the first argument (dirfd)
                    unsigned long flags = regs.rdx; // rdx contains the third argument (flags)
                    unsigned long mode = regs.r10;  // r10 contains the fourth argument (mode)

                    string node_ip = ch.getNode(abs_filename);
                    // if (pathToFd.getKey(filename) == -1) {
                    //     node_ip = ch.getNode(filename);
                    // } else {
                    //     node_ip = jsonManager.getKey(to_string(pathToFd.getKey(filename)))[0][0];
                    // }
                    int ip_index = findIpIndex(node_ip.c_str());

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
                        regs.rax = response.return_val();
                        regs.orig_rax = -1;

                        // Add to map
                        fdToAbsolutePath[response.return_val()] = absolutePath;
                        // vector<tuple<string, int>> info = {{node_ip, response.return_val()}};
                        // jsonManager.editKey(to_string(response.return_val()), info);
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

                string node_ip = ch.getNode(fdToAbsolutePath[fd]);
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
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            // Read from file
            else if (syscall_num == SYS_read)
            {
                unsigned long fd = regs.rdi;          // rdi contains the first argument (fd)
                unsigned long buffer_addr = regs.rsi; // rsi contains the second argument (buf)
                unsigned long count = regs.rdx;       // rdx contains the third argument (count)

                // string node_ip = jsonManager.getKey(to_string(fd))[0][0];
                string node_ip = ch.getNode(fdToAbsolutePath[fd]);
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
                
                // string node_ip = jsonManager.getKey(to_string(fd))[0][0];
                string node_ip = ch.getNode(fdToAbsolutePath[fd]);
                int ip_index = findIpIndex(node_ip.c_str());

                read_memory(child_pid, buffer_addr, buffer, count);

                std::string data = buffer;

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
                ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
            }

            else if (syscall_num == SYS_chdir)
            {
                // Trace out the buffer
                unsigned long buffer_addr = regs.rdi;
                read_memory(child_pid, buffer_addr, buffer, MAX_BUFFER_SIZE);
                absolutePath += buffer;

                for (int i = 0; i < NUM_INTERMEDIARIES; i++) {
                    // Serialize
                    string data = buffer;
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
                    if (response.return_val() != -1)
                    {
                        regs.rax = response.return_val();
                        regs.orig_rax = -1;
                    }
                    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                }
            }

            else if (syscall_num == SYS_mkdir)
            {
                // Trace out the buffer and mode
                unsigned long buffer_addr = regs.rdi;
                unsigned long mode = regs.rsi;
                read_memory(child_pid, buffer_addr, buffer, MAX_BUFFER_SIZE);

                for (int i = 0; i < NUM_INTERMEDIARIES; i++) {
                    // Serialize
                    string data = buffer;
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
                    response.ParseFromString(serialized_data);

                    // Change return value
                    if (response.return_val() != -1)
                    {
                        regs.rax = response.return_val();
                        regs.orig_rax = -1;
                    }
                    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
                }
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
                const char *response_buf = response.buffer().c_str();
                cout << response.buffer() << endl;

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
