#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <seccomp.h>
#include <errno.h>
#include "../include/seccomp_utils.h"

int apply_seccomp_filter(const char *mode, char **syscalls, int num_syscalls, int verbose) {
    scmp_filter_ctx ctx;

    if (strcmp(mode, "allow") == 0) {
        ctx = seccomp_init(SCMP_ACT_KILL);
        if (verbose) {
            printf("[SECCOMP] Mode: ALLOW (default: KILL)\n");
        }
    } else if (strcmp(mode, "block") == 0) {
        ctx = seccomp_init(SCMP_ACT_ALLOW);
        if (verbose) {
            printf("[SECCOMP] Mode: BLOCK (default: ALLOW)\n");
        }
    } else {
        fprintf(stderr, "Error: Invalid mode '%s'. Must be 'allow' or 'block'\n", mode);
        return -1;
    }

    if (ctx == NULL) {
        perror("Failed to initialize seccomp context");
        return -1;
    }

    for (int i = 0; i < num_syscalls; i++) {
        int syscall_num = seccomp_syscall_resolve_name(syscalls[i]);
        
        if (syscall_num == __NR_SCMP_ERROR) {
            fprintf(stderr, "Warning: Unable to resolve syscall '%s'\n", syscalls[i]);
            continue;
        }

        int ret;
        if (strcmp(mode, "allow") == 0) {
            ret = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_num, 0);
            if (verbose) {
                printf("[SECCOMP] Allowing syscall: %s (%d)\n", syscalls[i], syscall_num);
            }
        } else {
            ret = seccomp_rule_add(ctx, SCMP_ACT_KILL, syscall_num, 0);
            if (verbose) {
                printf("[SECCOMP] Blocking syscall: %s (%d)\n", syscalls[i], syscall_num);
            }
        }

        if (ret < 0) {
            fprintf(stderr, "Error adding rule for syscall '%s': %s\n", 
                    syscalls[i], strerror(-ret));
            seccomp_release(ctx);
            return -1;
        }
    }

    if (verbose) {
        printf("[SECCOMP] Loading filter into kernel...\n");
    }

    int ret = seccomp_load(ctx);
    seccomp_release(ctx);
    
    if (ret < 0) {
        fprintf(stderr, "Error loading seccomp filter: %s\n", strerror(-ret));
        return -1;
    }

    return 0;
}
