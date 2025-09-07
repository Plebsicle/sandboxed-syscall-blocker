#include <seccomp.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>

char* read_file(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);
    char* data = malloc(len + 1);
    fread(data, 1, len, f);
    fclose(f);
    data[len] = '\0';
    return data;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s policy.json\n", argv[0]);
        return 1;
    }

    char* json_data = read_file(argv[1]);
    if (!json_data) {
        perror("read_file");
        return 1;
    }

    cJSON *json = cJSON_Parse(json_data);
    cJSON *array = cJSON_GetObjectItem(json, "allowed_syscalls");

    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL);

    cJSON *item;
    cJSON_ArrayForEach(item, array) {
        const char* name = item->valuestring;
        int num = seccomp_syscall_resolve_name(name);
        if (num != __NR_SCMP_ERROR) {
            // here the validy is checked
            seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0);
        }
    }

    seccomp_load(ctx);

    // Demo syscalls
    write(1, "Hello!\n", 7);
    __pid_t x =   getpid(); // allowed only if in JSON
    printf("%d",x);
    cJSON_Delete(json);
    free(json_data);
    seccomp_release(ctx);
    return 0;
}
