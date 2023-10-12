#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <elf.h>
#include <sys/uio.h>  // for struct iovec

#include "syscall_arm64.h"

void child() {
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD + BPF_W + BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, __NR_write, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE),
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = {
        .len = (unsigned short)(sizeof(filter)/sizeof(filter[0])),
        .filter = filter,
    };

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        exit(1);
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("prctl(SECCOMP)");
        exit(1);
    }

    write(STDOUT_FILENO, "Hello, World!\n", 13);  // This will be intercepted
    exit(0);
}

void parent(pid_t child_pid) {
    int status;
    struct iovec iov;
    struct user_pt_regs regs;
    int entryexit = 0;  // 用于跟踪系统调用的入口和退出点

    iov.iov_base = &regs;
    iov.iov_len = sizeof(regs);

    while (waitpid(child_pid, &status, 0)) {
        if (WIFEXITED(status) || WIFSIGNALED(status))
            break;

        if (WIFSTOPPED(status)) {
            // 当停止是由于系统调用引起时
            if (status >> 8 == (SIGTRAP | 0x80)) {
                if (ptrace(PTRACE_GETREGSET, child_pid, NT_PRSTATUS, &iov) == -1) {
                    perror("ptrace");
                    exit(1);
                }
                // 通过 entryexit 变量区分系统调用的入口和退出点
                if (entryexit == 0) {
                    printf("System Call Entry: Number %llu\n", regs.regs[8]);
                    entryexit = 1;
                } else {
                    printf("System Call Exit: Number %llu\n", regs.regs[8]);
                    entryexit = 0;
                }
            }
            // Check if the stop was caused by a seccomp event
            else if ((status >> 8) == (SIGTRAP | (PTRACE_EVENT_SECCOMP << 8))) {
                printf("Parent: PTRACE_EVENT_SECCOMP event received.\n");
            }

            if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
                perror("ptrace");
                exit(1);
            }
        }
    }
}

int main() {
    pid_t child_pid = fork();
    if (child_pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, 0, 0) == -1) {
            perror("ptrace");
            exit(1);
        }
        kill(getpid(), SIGSTOP);  // Stop until the parent is ready to continue
        child();
    } else if (child_pid > 0) {
        int status;
        waitpid(child_pid, &status, 0);  // Wait for child to stop
        if (ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESECCOMP | PTRACE_O_TRACESYSGOOD) == -1) {
            perror("ptrace");
            exit(1);
        }
        ptrace(PTRACE_SYSCALL, child_pid, 0, 0);  // Continue the child
        parent(child_pid);
    } else {
        perror("fork");
        exit(1);
    }
    return 0;
}

