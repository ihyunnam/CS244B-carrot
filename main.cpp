#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include "sysnames.h"
// #include <cstring>

#include <sys/syscall.h>

#include <unistd.h>


#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <iostream>
#include <cstring>

#define PORT 12346
using namespace std;

int main(int argc, char* argv[]) {

    int sockfd_send;
    struct sockaddr_in servaddr_send;

    if ((sockfd_send = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        cerr << "Socket creation failed" << endl;
        return -1;
    }

    // Filling server information
    servaddr_send.sin_family = AF_INET;
    servaddr_send.sin_addr.s_addr = INADDR_ANY;
    servaddr_send.sin_port = htons(PORT);
    
    if (bind(sockfd_send, (const struct sockaddr *)&servaddr_send, sizeof(servaddr_send)) < 0) {
        cerr << "Binding failed 1" << endl;
        return -1;
    }

    if (argc == 1) {
        exit(0);
    }

    char* chargs[argc];
    int i = 0;

    while (i < argc - 1) {
        chargs[i] = argv[i+1];
        i++;
    }

    pid_t child_pid = fork();
    chargs[i] = NULL;
    if (child_pid == -1) {
        // Error handling
        fprintf(stderr, "Failed to fork");
        return 1;
    } else if (child_pid == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execvp(chargs[0], chargs);
    } else {
        // Parent process
        int status;
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status)) {
            printf("Child process exited normally");
            return 0;
        }

        while (true) {
            ptrace(PTRACE_SYSCALL, child_pid, nullptr, nullptr);
            waitpid(child_pid, &status, 0);
            if (WIFEXITED(status)) {
                break;
            }
            
            // Check if syscall was made
            struct user_regs_struct regs;
            ptrace(PTRACE_GETREGS, child_pid, nullptr, &regs);
            long syscall_num = regs.orig_rax;
            if (syscall_num == SYS_sendto) {
                char buffer[1024];
                for (int i = 0; i < 1024; i+=1) {
                    buffer[i] = ptrace(PTRACE_PEEKDATA, child_pid, regs.rsi + i, 0);
                    if (buffer[i] == '\0') {
                        break;
                    }
                }

                fprintf(stderr, "buffer %s\n", buffer);
                struct sockaddr_in dest_addr;
                for (long unsigned int i = 0; i < sizeof(struct sockaddr_in); i+=1) {
                    *((char *)(&dest_addr)+i) = ptrace(PTRACE_PEEKDATA, child_pid, regs.r8 + i, 0);
                }
                fprintf(stderr, "sin_port %d\n", ntohs(dest_addr.sin_port));
                fprintf(stderr, "sin_addr %s\n", inet_ntoa(dest_addr.sin_addr));
                sendto(sockfd_send, buffer, strlen(buffer), 0, (const struct sockaddr *) &dest_addr, sizeof(dest_addr));
            }
            fprintf(stderr, "system call number %ld name %s from pid %d\n", syscall_num, callname(syscall_num), child_pid);
        }
    }
    return 0;
}



