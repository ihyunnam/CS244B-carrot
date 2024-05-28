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
#include <cstring>

// Code for protobufs
#include "protobufs/messages/message.pb.h"
#include "protobufs/messages/message.pb.cc"

// Default constants for tracer
#define PORT 12345
#define NUM_INTERMEDIARIES 1
using namespace std;

// Defining intermediaries
struct sockaddr_in intermediaries[NUM_INTERMEDIARIES];
const char *ip_addresses[NUM_INTERMEDIARIES] = {
    "34.132.138.246"};
// "34.41.143.79"};

/*
 * Interpose a sendto sys call
 */
void interpose_send(pid_t child_pid, struct user_regs_struct regs, int sockfd_send, bool is_intermediary)
{
    // Retrieve buffer
    // fprintf(stderr, "Sending Message\n\n");
    char buffer[1024];
    for (int i = 0; i < 1024; i += 1)
    {
        buffer[i] = ptrace(PTRACE_PEEKDATA, child_pid, regs.rsi + i, 0);
        if (buffer[i] == '\0')
        {
            break;
        }
    }
    // fprintf(stderr, "Message: %s\n", buffer);

    // Read in and check destination address information
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    for (long unsigned int i = 0; i < sizeof(struct sockaddr_in); i += 1)
    {
        *((char *)(&dest_addr) + i) = ptrace(PTRACE_PEEKDATA, child_pid, regs.r8 + i, 0);
    }

    // Print out port and address of destination address
    // fprintf(stderr, "Destination Port: %d\n", ntohs(dest_addr.sin_port));
    // fprintf(stderr, "Destination Address: %s\n\n", inet_ntoa(dest_addr.sin_addr));

    // Create a message
    CarrotMessage message;
    message.set_message(buffer);
    message.set_port(ntohs(dest_addr.sin_port));
    message.set_ip_address(inet_ntoa(dest_addr.sin_addr));

    // Serialize the message
    string serialized_data;
    message.SerializeToString(&serialized_data);

    // Make child process not sendto
    regs.orig_rax = SYS_getpid;
    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);

    // Also send to client
    if (is_intermediary)
    {
        sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&dest_addr, sizeof(dest_addr));
    }
    else
    {
        sendto(sockfd_send, serialized_data.c_str(), serialized_data.length(), 0, (const struct sockaddr *)&intermediaries[0], sizeof(intermediaries[0]));
    }
}

/*
 * Interpose a receive syscall
 */
void interpose_receive(pid_t child_pid, struct user_regs_struct regs, int sockfd_send)
{
    // Get the source address to read in from recvfrom
    fprintf(stderr, "Receiving Message\n\n");
    struct sockaddr_in source_addr;
    for (long unsigned int i = 0; i < sizeof(struct sockaddr_in); i += 1)
    {
        *((char *)(&source_addr) + i) = ptrace(PTRACE_PEEKDATA, child_pid, regs.r8 + i, 0);
    }

    // Receive process as the image
    char buffer[1024];
    socklen_t len;
    recvfrom(sockfd_send, buffer, 1024, 0, (struct sockaddr *)&source_addr, &len);

    // Print out port and address of destination address
    fprintf(stderr, "Source Address: %s\n", inet_ntoa(source_addr.sin_addr));
    fprintf(stderr, "Source Port: %d\n", ntohs(source_addr.sin_port));

    // Deserialize the message
    CarrotMessage deserialized_message;
    string serialized_data = buffer;
    deserialized_message.ParseFromString(serialized_data);

    // Send message back to child process
    const string &message = deserialized_message.message();
    int length = message.length() + 1; // include null terminator
    for (int i = 0; i < length; i += sizeof(long))
    {
        long data;
        memcpy(&data, message.c_str() + i, sizeof(long));
        ptrace(PTRACE_POKEDATA, child_pid, regs.rsi + i, data);
    }

    // Set up destination info
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;

    // Get destination information from the deserialized string
    dest_addr.sin_port = htons(deserialized_message.port());
    inet_pton(AF_INET, deserialized_message.ip_address().c_str(), &dest_addr.sin_addr);

    // Send source information back
    for (long unsigned int i = 0; i < sizeof(struct sockaddr_in); i += sizeof(long))
    {
        long data;
        memcpy(&data, ((char *)(&dest_addr)) + i, sizeof(long));
        ptrace(PTRACE_POKEDATA, child_pid, regs.r8 + i, data);
    }

    // Set back to original regs
    regs.orig_rax = SYS_getpid;
    ptrace(PTRACE_SETREGS, child_pid, NULL, &regs);
}

int main(int argc, char *argv[])
{
    // Defining intermediaries
    bool is_intermediary = false;
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

    // Create a socket to send out information
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

    // Also check if intermediary
    while (i < argc - 1)
    {
        chargs[i] = argv[i + 1];
        if (strcmp(chargs[i], "./intermediary") == 0)
        {
            is_intermediary = true;
        }
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
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status))
        {
            printf("Child process exited normally");
            return 0;
        }

        while (true)
        {
            // Trace syscalls from the child process
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

            // If on sendto or receive, interpose
            if (syscall_num == SYS_sendto)
            {
                // fprintf("Cool");
                interpose_send(child_pid, regs, sockfd_send, is_intermediary);
            }
            if (syscall_num == SYS_recvfrom)
            {
                interpose_receive(child_pid, regs, sockfd_send);
            }
        }
    }
    return 0;
}
