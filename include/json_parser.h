#ifndef JSON_PARSER_H
#define JSON_PARSER_H

typedef struct {
    char *mode;
    char **syscalls;
    int num_syscalls;
} Policy;

Policy *parse_policy(const char *filename);

void free_policy(Policy *policy);

#endif
