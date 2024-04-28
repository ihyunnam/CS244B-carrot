#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>
#include "sysnames.h"

int main(int argc, char* argv[]) {
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
            fprintf(stderr, "system call number %ld name %s from pid %d\n", syscall_num, callname(syscall_num), child_pid);
        }
    }
    return 0;
}



