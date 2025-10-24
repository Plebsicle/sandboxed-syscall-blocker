#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/prctl.h>
#include "../include/json_parser.h"
#include "../include/seccomp_utils.h"
#include "../include/ptrace_block.h"

void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s --policy <policy.json> --exec <program> [args...] [OPTIONS]\n", program_name);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  --policy <file>         Path to JSON policy file\n");
    fprintf(stderr, "  --exec <program>        Program to execute in sandbox\n");
    fprintf(stderr, "  --verbose               Enable verbose output\n");
    fprintf(stderr, "  --trace-block-dynamic   Enable dynamic ptrace-based syscall blocking\n");
    fprintf(stderr, "\nExamples:\n");
    fprintf(stderr, "  Static mode:\n");
    fprintf(stderr, "    %s --policy policies/ls_policy.json --exec /bin/ls\n", program_name);
    fprintf(stderr, "\n  Dynamic mode:\n");
    fprintf(stderr, "    %s --policy policies/base_policy.json --exec /bin/ls --trace-block-dynamic\n", program_name);
}

int parse_args(int argc, char *argv[], char **policy_file, char ***exec_args, int *verbose, int *dynamic_mode) {
    *policy_file = NULL;
    *exec_args = NULL;
    *verbose = 0;
    *dynamic_mode = 0;

    int exec_idx = -1;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--policy") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --policy requires an argument\n");
                return -1;
            }
            *policy_file = argv[++i];
        } else if (strcmp(argv[i], "--exec") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "Error: --exec requires an argument\n");
                return -1;
            }
            exec_idx = i + 1;
            break;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            *verbose = 1;
        } else if (strcmp(argv[i], "--trace-block-dynamic") == 0) {
            *dynamic_mode = 1;
        } else {
            fprintf(stderr, "Error: Unknown option '%s'\n", argv[i]);
            return -1;
        }
    }

    if (!*policy_file) {
        fprintf(stderr, "Error: --policy is required\n");
        return -1;
    }

    if (exec_idx == -1) {
        fprintf(stderr, "Error: --exec is required\n");
        return -1;
    }

    int exec_argc = argc - exec_idx;
    *exec_args = malloc(sizeof(char *) * (exec_argc + 1));
    if (!*exec_args) {
        perror("malloc");
        return -1;
    }

    for (int i = 0; i < exec_argc; i++) {
        if (strcmp(argv[exec_idx + i], "--verbose") == 0 ||
            strcmp(argv[exec_idx + i], "--trace-block-dynamic") == 0) {
            exec_argc--;
            i--;
            continue;
        }
        (*exec_args)[i] = argv[exec_idx + i];
    }
    (*exec_args)[exec_argc] = NULL;

    return 0;
}

int main(int argc, char *argv[]) {
    char *policy_file = NULL;
    char **exec_args = NULL;
    int verbose = 0;
    int dynamic_mode = 0;

    if (parse_args(argc, argv, &policy_file, &exec_args, &verbose, &dynamic_mode) < 0) {
        print_usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (verbose) {
        printf("[SANDBOX] Starting sandbox...\n");
        printf("[SANDBOX] Policy file: %s\n", policy_file);
        printf("[SANDBOX] Target program: %s\n", exec_args[0]);
    }

    Policy *policy = parse_policy(policy_file);
    if (!policy) {
        fprintf(stderr, "Error: Failed to parse policy file\n");
        free(exec_args);
        return EXIT_FAILURE;
    }

    if (verbose) {
        printf("[SANDBOX] Policy loaded: mode=%s, syscalls=%d\n", 
               policy->mode, policy->num_syscalls);
        if (dynamic_mode) {
            printf("[SANDBOX] Mode: DYNAMIC (ptrace-based interactive blocking)\n");
        } else {
            printf("[SANDBOX] Mode: STATIC (seccomp-based)\n");
        }
    }

    if (dynamic_mode) {
        int exit_status = run_with_ptrace_dynamic(policy, exec_args, verbose);
        
        free_policy(policy);
        free(exec_args);
        
        return (exit_status < 0) ? EXIT_FAILURE : exit_status;
    }

    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        free_policy(policy);
        free(exec_args);
        return EXIT_FAILURE;
    }

    if (pid == 0) {
        if (verbose) {
            printf("[CHILD] Applying seccomp filter...\n");
            printf("[CHILD] Executing: %s\n", exec_args[0]);
            fflush(stdout);
        }

        if (apply_seccomp_filter(policy->mode, policy->syscalls, 
                                 policy->num_syscalls, verbose) < 0) {
            fprintf(stderr, "[CHILD] Failed to apply seccomp filter\n");
            exit(EXIT_FAILURE);
        }

        execvp(exec_args[0], exec_args);
        
        perror("execvp");
        exit(EXIT_FAILURE);
    } else {
        if (verbose) {
            printf("[PARENT] Child process started with PID %d\n", pid);
            printf("[PARENT] Waiting for child to complete...\n");
        }

        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status)) {
            int exit_code = WEXITSTATUS(status);
            if (verbose || exit_code != 0) {
                printf("[PARENT] Child exited with status: %d\n", exit_code);
            }
        } else if (WIFSIGNALED(status)) {
            int signal = WTERMSIG(status);
            printf("[PARENT] Child killed by signal: %d", signal);
            if (signal == 31) {
                printf(" (SIGSYS - seccomp violation)");
            }
            printf("\n");
        }
    }

    free_policy(policy);
    free(exec_args);

    return EXIT_SUCCESS;
}
