#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/select.h>
#include "../include/dynamic_prompt.h"

#define INITIAL_CAPACITY 32
#define TIMEOUT_SECONDS 10

DynamicAllowlist *init_dynamic_allowlist() {
    DynamicAllowlist *allowlist = malloc(sizeof(DynamicAllowlist));
    if (!allowlist) {
        return NULL;
    }

    allowlist->syscalls = malloc(sizeof(char *) * INITIAL_CAPACITY);
    allowlist->syscall_nums = malloc(sizeof(int) * INITIAL_CAPACITY);
    
    if (!allowlist->syscalls || !allowlist->syscall_nums) {
        free(allowlist->syscalls);
        free(allowlist->syscall_nums);
        free(allowlist);
        return NULL;
    }

    allowlist->count = 0;
    allowlist->capacity = INITIAL_CAPACITY;

    return allowlist;
}

int is_in_dynamic_allowlist(DynamicAllowlist *allowlist, int syscall_num) {
    if (!allowlist) {
        return 0;
    }

    for (int i = 0; i < allowlist->count; i++) {
        if (allowlist->syscall_nums[i] == syscall_num) {
            return 1;
        }
    }

    return 0;
}

int add_to_dynamic_allowlist(DynamicAllowlist *allowlist, const char *syscall_name, int syscall_num) {
    if (!allowlist) {
        return -1;
    }

    if (is_in_dynamic_allowlist(allowlist, syscall_num)) {
        return 0;
    }

    if (allowlist->count >= allowlist->capacity) {
        int new_capacity = allowlist->capacity * 2;
        char **new_syscalls = realloc(allowlist->syscalls, sizeof(char *) * new_capacity);
        int *new_nums = realloc(allowlist->syscall_nums, sizeof(int) * new_capacity);

        if (!new_syscalls || !new_nums) {
            free(new_syscalls);
            free(new_nums);
            return -1;
        }

        allowlist->syscalls = new_syscalls;
        allowlist->syscall_nums = new_nums;
        allowlist->capacity = new_capacity;
    }

    allowlist->syscalls[allowlist->count] = strdup(syscall_name);
    if (!allowlist->syscalls[allowlist->count]) {
        return -1;
    }

    allowlist->syscall_nums[allowlist->count] = syscall_num;
    allowlist->count++;

    return 0;
}

static int read_char_with_timeout(char *ch, int timeout_sec) {
    fd_set readfds;
    struct timeval tv;
    
    FD_ZERO(&readfds);
    FD_SET(STDIN_FILENO, &readfds);
    
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    
    int ret = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);
    
    if (ret == -1) {
        perror("select");
        return -1;
    } else if (ret == 0) {
        return 0;
    } else {
        if (read(STDIN_FILENO, ch, 1) != 1) {
            return -1;
        }
        return 1;
    }
}

int prompt_user_for_syscall(const char *syscall_name, int syscall_num) {
    char response;
    
    printf("\n[DYNAMIC] Unknown syscall detected: %s (%d)\n", syscall_name, syscall_num);
    printf("Allow this syscall? (y/n) [timeout in %d seconds, default=block]: ", TIMEOUT_SECONDS);
    fflush(stdout);

    int read_result = read_char_with_timeout(&response, TIMEOUT_SECONDS);
    
    if (read_result == 0) {
        printf("\n[DYNAMIC] Timeout - blocking syscall\n");
        return 0;
    } else if (read_result == -1) {
        printf("\n[DYNAMIC] Error reading input - blocking syscall\n");
        return 0;
    }

    char c;
    while (read(STDIN_FILENO, &c, 1) == 1 && c != '\n');

    if (response == 'y' || response == 'Y') {
        printf("[DYNAMIC] User allowed syscall: %s\n", syscall_name);
        return 1;
    } else {
        printf("[DYNAMIC] User blocked syscall: %s\n", syscall_name);
        return 0;
    }
}

void free_dynamic_allowlist(DynamicAllowlist *allowlist) {
    if (!allowlist) {
        return;
    }

    if (allowlist->syscalls) {
        for (int i = 0; i < allowlist->count; i++) {
            free(allowlist->syscalls[i]);
        }
        free(allowlist->syscalls);
    }

    if (allowlist->syscall_nums) {
        free(allowlist->syscall_nums);
    }

    free(allowlist);
}
