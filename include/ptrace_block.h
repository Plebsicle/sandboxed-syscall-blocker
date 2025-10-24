#ifndef PTRACE_BLOCK_H
#define PTRACE_BLOCK_H

#include "json_parser.h"

int run_with_ptrace_dynamic(Policy *policy, char **exec_args, int verbose);

#endif
