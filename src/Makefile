CC = gcc
CFLAGS = -Wall -Wextra -I../include -I/usr/include/cjson
LDFLAGS = -lseccomp -lcjson

TARGET = sandbox
SRCS = sandbox.c seccomp_utils.c json_parser.c ptrace_block.c dynamic_prompt.c
OBJS = $(SRCS:.c=.o)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@echo "Build complete: $(TARGET)"

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)
	@echo "Cleaned build artifacts"

install: $(TARGET)
	sudo cp $(TARGET) /usr/local/bin/
	@echo "Installed to /usr/local/bin/$(TARGET)"

uninstall:
	sudo rm -f /usr/local/bin/$(TARGET)
	@echo "Uninstalled from /usr/local/bin/$(TARGET)"

test: $(TARGET)
	@echo "Testing with ls policy..."
	./$(TARGET) --policy ../policies/ls_policy.json --exec /bin/ls --verbose
	@echo ""
	@echo "Testing with base policy..."
	./$(TARGET) --policy ../policies/base_policy.json --exec /bin/echo "Hello from sandbox"

help:
	@echo "Seccomp Sandbox Makefile"
	@echo "========================"
	@echo "Targets:"
	@echo "  all       - Build the sandbox tool (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to /usr/local/bin (requires sudo)"
	@echo "  uninstall - Remove from /usr/local/bin (requires sudo)"
	@echo "  test      - Run basic tests"
	@echo "  help      - Display this help message"

.PHONY: all clean install uninstall test help
