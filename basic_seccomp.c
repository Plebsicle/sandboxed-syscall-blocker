#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    // Initialize seccomp context: default action is KILL
    // pass in a default value inside the _init func for initing the seccomp filter
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);
    if (!ctx) {
        perror("seccomp_init");
        exit(1);
    }
    // ctx is the seccomp filter
    // basic sys calls other than the Write Syscall
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(brk), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0);
    seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(munmap), 0);

    // Load the filter
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        exit(1);
    }

    // Allowed: write
    write(STDOUT_FILENO, "Hello via write()\n", 18);

    // Forbidden: getpid (should kill process)
    // pid_t pid = getpid();
    // printf("PID is %d\n", pid);

    seccomp_release(ctx);
    return 0;
}
