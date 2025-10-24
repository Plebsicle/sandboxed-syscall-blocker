#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "../include/json_parser.h"

static char *read_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (!file) {
        perror("Failed to open policy file");
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);

    char *buffer = malloc(size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    size_t read_size = fread(buffer, 1, size, file);
    buffer[read_size] = '\0';
    fclose(file);

    return buffer;
}

Policy *parse_policy(const char *filename) {
    char *json_str = read_file(filename);
    if (!json_str) {
        return NULL;
    }

    cJSON *json = cJSON_Parse(json_str);
    free(json_str);

    if (!json) {
        fprintf(stderr, "Error parsing JSON: %s\n", cJSON_GetErrorPtr());
        return NULL;
    }

    Policy *policy = malloc(sizeof(Policy));
    if (!policy) {
        cJSON_Delete(json);
        return NULL;
    }

    cJSON *mode = cJSON_GetObjectItem(json, "mode");
    if (!mode || !cJSON_IsString(mode)) {
        fprintf(stderr, "Error: 'mode' field missing or invalid\n");
        free(policy);
        cJSON_Delete(json);
        return NULL;
    }
    policy->mode = strdup(mode->valuestring);

    cJSON *syscalls = cJSON_GetObjectItem(json, "syscalls");
    if (!syscalls || !cJSON_IsArray(syscalls)) {
        fprintf(stderr, "Error: 'syscalls' field missing or invalid\n");
        free(policy->mode);
        free(policy);
        cJSON_Delete(json);
        return NULL;
    }

    policy->num_syscalls = cJSON_GetArraySize(syscalls);
    policy->syscalls = malloc(sizeof(char *) * policy->num_syscalls);
    if (!policy->syscalls) {
        free(policy->mode);
        free(policy);
        cJSON_Delete(json);
        return NULL;
    }

    for (int i = 0; i < policy->num_syscalls; i++) {
        cJSON *syscall = cJSON_GetArrayItem(syscalls, i);
        if (cJSON_IsString(syscall)) {
            policy->syscalls[i] = strdup(syscall->valuestring);
        } else {
            for (int j = 0; j < i; j++) {
                free(policy->syscalls[j]);
            }
            free(policy->syscalls);
            free(policy->mode);
            free(policy);
            cJSON_Delete(json);
            return NULL;
        }
    }

    cJSON_Delete(json);
    return policy;
}

void free_policy(Policy *policy) {
    if (!policy) return;

    if (policy->mode) {
        free(policy->mode);
    }

    if (policy->syscalls) {
        for (int i = 0; i < policy->num_syscalls; i++) {
            if (policy->syscalls[i]) {
                free(policy->syscalls[i]);
            }
        }
        free(policy->syscalls);
    }

    free(policy);
}
