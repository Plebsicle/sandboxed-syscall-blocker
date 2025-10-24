#ifndef SECCOMP_UTILS_H
#define SECCOMP_UTILS_H

#include <seccomp.h>

int apply_seccomp_filter(const char *mode, char **syscalls, int num_syscalls, int verbose);

#endif
