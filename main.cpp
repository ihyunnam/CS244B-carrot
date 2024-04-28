#include <iostream>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/user.h>

int main() {
    pid_t child_pid = fork();
    if (child_pid == -1) {
        // Error handling
        std::cerr << "Failed to fork\n";
        return 1;
    } else if (child_pid == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl("/bin/ping", "ping", "8.8.8.8", nullptr); // Change IP address as needed
    } else {
        // Parent process
        int status;
        waitpid(child_pid, &status, 0);
        if (WIFEXITED(status)) {
            std::cout << "Child process exited normally\n";
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
            std::cout << "Syscall number: " << regs.orig_rax << "\n"; // The syscall number is in register x8
        }
    }
    return 0;
}