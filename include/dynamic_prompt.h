#ifndef DYNAMIC_PROMPT_H
#define DYNAMIC_PROMPT_H

typedef struct {
    char **syscalls;
    int *syscall_nums;
    int count;
    int capacity;
} DynamicAllowlist;

DynamicAllowlist *init_dynamic_allowlist();

int is_in_dynamic_allowlist(DynamicAllowlist *allowlist, int syscall_num);

int add_to_dynamic_allowlist(DynamicAllowlist *allowlist, const char *syscall_name, int syscall_num);

int prompt_user_for_syscall(const char *syscall_name, int syscall_num);

void free_dynamic_allowlist(DynamicAllowlist *allowlist);

#endif
