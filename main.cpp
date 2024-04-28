#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main() {
    pid_t child_pid = fork();

    if (child_pid == 0) {
        // Child process
        ptrace(PTRACE_TRACEME, 0, nullptr, nullptr);
        execl("/bin/ls", "ls", nullptr);
    } else if (child_pid > 0) {
        // Parent process
        int status;
        waitpid(child_pid, &status, 0);
        
        if (WIFSTOPPED(status)) {
            std::cout << "Child process stopped\n";
        }

        // Do something with the traced process, e.g., examine its memory, registers, etc.

        ptrace(PTRACE_CONT, child_pid, nullptr, nullptr); // Continue execution
        waitpid(child_pid, &status, 0);

        if (WIFEXITED(status)) {
            std::cout << "Child process exited\n";
        }
    } else {
        std::cerr << "Fork failed\n";
        return 1;
    }

    return 0;
}
