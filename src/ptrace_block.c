#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/reg.h>
#include <seccomp.h>
#include <errno.h>
#include "../include/ptrace_block.h"
#include "../include/dynamic_prompt.h"

static int is_in_base_policy(Policy *policy, int syscall_num) {
    if (!policy || !policy->syscalls) {
        return 0;
    }

    for (int i = 0; i < policy->num_syscalls; i++) {
        int resolved_num = seccomp_syscall_resolve_name(policy->syscalls[i]);
        if (resolved_num == syscall_num) {
            return 1;
        }
    }

    return 0;
}

static const char *get_syscall_name(int syscall_num) {
    static char buffer[64];
    const char *name = seccomp_syscall_resolve_num_arch(SCMP_ARCH_NATIVE, syscall_num);
    
    if (name) {
        return name;
    }
    
    snprintf(buffer, sizeof(buffer), "syscall_%d", syscall_num);
    return buffer;
}

int run_with_ptrace_dynamic(Policy *policy, char **exec_args, int verbose) {
    pid_t child_pid;
    int status;
    DynamicAllowlist *dynamic_allowlist = NULL;

    dynamic_allowlist = init_dynamic_allowlist();
    if (!dynamic_allowlist) {
        fprintf(stderr, "[PTRACE] Failed to initialize dynamic allowlist\n");
        return -1;
    }

    if (verbose) {
        printf("[PTRACE] Starting dynamic trace-block mode\n");
        printf("[PTRACE] Base policy: %s mode with %d syscalls\n", 
               policy->mode, policy->num_syscalls);
    }

    child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        free_dynamic_allowlist(dynamic_allowlist);
        return -1;
    }

    if (child_pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) == -1) {
            perror("ptrace PTRACE_TRACEME");
            exit(EXIT_FAILURE);
        }

        raise(SIGSTOP);

        execvp(exec_args[0], exec_args);
        
        perror("execvp");
        exit(EXIT_FAILURE);
    } else {
        if (verbose) {
            printf("[PTRACE] Tracing child process PID: %d\n", child_pid);
            printf("[PTRACE] Intercepting syscalls...\n\n");
        }

        waitpid(child_pid, &status, 0);

        ptrace(PTRACE_SETOPTIONS, child_pid, 0, PTRACE_O_TRACESYSGOOD);

        int syscall_enter = 1;
        int last_blocked_syscall = -1;

        while (1) {
            if (ptrace(PTRACE_SYSCALL, child_pid, 0, 0) == -1) {
                perror("ptrace PTRACE_SYSCALL");
                break;
            }

            if (waitpid(child_pid, &status, 0) == -1) {
                perror("waitpid");
                break;
            }

            if (WIFEXITED(status)) {
                if (verbose) {
                    printf("\n[PTRACE] Child exited with status: %d\n", WEXITSTATUS(status));
                }
                break;
            }

            if (WIFSIGNALED(status)) {
                printf("\n[PTRACE] Child killed by signal: %d\n", WTERMSIG(status));
                break;
            }

            struct user_regs_struct regs;
            if (ptrace(PTRACE_GETREGS, child_pid, 0, &regs) == -1) {
                perror("ptrace PTRACE_GETREGS");
                break;
            }

            long syscall_num = regs.orig_rax;

            if (syscall_enter) {
                int is_allowed = 0;
                const char *syscall_name = get_syscall_name(syscall_num);

                if (is_in_base_policy(policy, syscall_num)) {
                    is_allowed = 1;
                    if (verbose) {
                        printf("[TRACE] %s (%ld) → ALLOWED (base policy)\n", 
                               syscall_name, syscall_num);
                    }
                }
                else if (is_in_dynamic_allowlist(dynamic_allowlist, syscall_num)) {
                    is_allowed = 1;
                    if (verbose) {
                        printf("[TRACE] %s (%ld) → ALLOWED (dynamic buffer)\n", 
                               syscall_name, syscall_num);
                    }
                }
                else {
                    int user_decision = prompt_user_for_syscall(syscall_name, syscall_num);
                    
                    if (user_decision) {
                        add_to_dynamic_allowlist(dynamic_allowlist, syscall_name, syscall_num);
                        is_allowed = 1;
                        printf("[TRACE] %s (%ld) → TEMPORARILY ALLOWED (added to buffer)\n", 
                               syscall_name, syscall_num);
                    } else {
                        is_allowed = 0;
                        printf("[TRACE] %s (%ld) → BLOCKED (user decision)\n", 
                               syscall_name, syscall_num);
                    }
                }

                if (!is_allowed) {
                    regs.orig_rax = -1;
                    if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1) {
                        perror("ptrace PTRACE_SETREGS");
                    }
                    last_blocked_syscall = syscall_num;
                }
            } else {
                if (last_blocked_syscall != -1 && syscall_num == last_blocked_syscall) {
                    regs.rax = -EPERM;
                    if (ptrace(PTRACE_SETREGS, child_pid, 0, &regs) == -1) {
                        perror("ptrace PTRACE_SETREGS");
                    }
                    last_blocked_syscall = -1;
                }
            }

            syscall_enter = !syscall_enter;
        }

        if (verbose) {
            printf("\n[PTRACE] Dynamic allowlist entries: %d\n", dynamic_allowlist->count);
            printf("[PTRACE] Discarding dynamic buffer...\n");
        }

        free_dynamic_allowlist(dynamic_allowlist);

        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        
        return 0;
    }
}
