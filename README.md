# 🛡️ Seccomp-Based Process Sandbox Tool

## 📘 Overview
This project is a **Seccomp-BPF based Sandbox Framework** built in C using the **libseccomp** and **cJSON** libraries.  
It allows users to **run any Linux application inside a sandbox** that restricts which **system calls (syscalls)** the application can make — based on a **user-specified JSON policy**.

If the sandboxed process tries to use a blocked syscall, the kernel will prevent it (kill or log, depending on config).  

This tool demonstrates how low-level OS security mechanisms can be used to build isolation and confinement similar to containers.

---

## 🧩 Core Concept
Every process communicates with the kernel through syscalls.  
Seccomp (Secure Computing mode) allows a process to limit which syscalls are allowed.  
This tool provides:
- A **command-line interface** to specify:
  - the **target application** to run
  - the **syscalls policy JSON file**
- A **sandbox launcher** that:
  1. Parses the JSON policy
  2. Forks a child process
  3. Applies the Seccomp filter inside the child
  4. Replaces the child process using `execvp()` with the target program
  5. The parent monitors and reports the exit status

---

## 🧱 Features

### 🔹 Dual-Mode Operation

This sandbox supports **two enforcement modes**:

#### **1. Static Mode (Seccomp-BPF)**
- Fast, kernel-level enforcement
- Fixed policy loaded at startup
- Near-zero overhead
- Production-ready

#### **2. Dynamic Mode (Ptrace-based)**
- Interactive syscall monitoring
- Real-time user decisions
- Learning mode for policy development
- Runtime allowlist building

### 🔹 Core Features
- **Run any program sandboxed** using:
  ```bash
  ./sandbox --policy <policy.json> --exec /bin/ls
  ```
- **Per-program JSON policy** defining allowed syscalls
- **Two enforcement mechanisms**:
  - **Seccomp-BPF**: Kernel-level filtering (static mode)
  - **Ptrace**: Userspace interception (dynamic mode)
- **Customizable behavior**:
  - Kill on violation (static mode)
  - Prompt user for decision (dynamic mode)
  - Return EPERM on blocked syscalls
- **Real-time status reporting** from the parent process

### 🔹 Advanced Features
- Verbose mode to print which syscalls are allowed/blocked
- Interactive prompts with timeout safety (dynamic mode)
- In-memory dynamic allowlist buffer
- Support for both "allowlist" and "blocklist" JSON modes

---

## 📂 Project Structure
```
seccomp-sandbox/
├── src/
│   ├── sandbox.c             # main launcher with mode selection
│   ├── seccomp_utils.c       # seccomp filter setup (static mode)
│   ├── ptrace_block.c        # ptrace interception (dynamic mode)
│   ├── dynamic_prompt.c      # user interaction & buffer management
│   ├── json_parser.c         # reads and parses policy file
│   └── Makefile
├── policies/
│   ├── base_policy.json      # comprehensive allowlist
│   ├── ls_policy.json        # demo policy for /bin/ls
│   ├── python_policy.json    # demo policy for python3
│   └── minimal_policy.json   # minimal set for testing
├── include/
│   ├── seccomp_utils.h
│   ├── ptrace_block.h
│   ├── dynamic_prompt.h
│   └── json_parser.h
└── README.md
```

---

## ⚙️ Build Requirements

### 🧩 Dependencies
- **libseccomp** → for Seccomp API  
  ```bash
  sudo apt install libseccomp-dev
  ```
- **libcjson** → for JSON parsing  
  ```bash
  sudo apt install libcjson-dev
  ```
- **GCC or Clang**
- **Linux kernel ≥ 3.5**

### 🧰 Compile Command
If using Makefile:
```bash
cd src/
make
```

Or directly:
```bash
gcc src/sandbox.c src/seccomp_utils.c src/json_parser.c \
    -I/usr/include/cjson -Iinclude -lseccomp -lcjson -o src/sandbox
```

---

## 📜 JSON Policy Format

The policy file defines which syscalls are allowed or blocked.

### 1️⃣ Allowlist Example
```json
{
  "mode": "allow",
  "syscalls": [
    "read",
    "write",
    "exit",
    "exit_group",
    "brk",
    "mmap",
    "munmap",
    "arch_prctl",
    "newfstatat"
  ]
}
```
> In "allow" mode, only the listed syscalls are permitted. Everything else is blocked.

---

### 2️⃣ Blocklist Example
```json
{
  "mode": "block",
  "syscalls": ["socket", "execve", "openat"]
}
```
> In "block" mode, all syscalls are allowed except the listed ones.

---

## 🚀 Usage Examples

### Static Mode (Fast, Production)

Run `/bin/ls` under a safe policy:
```bash
cd src/
./sandbox --policy ../policies/ls_policy.json --exec /bin/ls
```

Run with verbose output:
```bash
./sandbox --policy ../policies/ls_policy.json --exec /bin/ls --verbose
```

Run Python interpreter:
```bash
./sandbox --policy ../policies/python_policy.json --exec /usr/bin/python3 -c "print('Hello from sandbox')"
```

### Dynamic Mode (Interactive, Learning) 🆕

Run with dynamic syscall blocking:
```bash
cd src/
./sandbox --policy ../policies/base_policy.json --trace-block-dynamic --exec /bin/ls
```

When an unknown syscall is detected, you'll be prompted:
```
[DYNAMIC] Unknown syscall detected: openat (257)
Allow this syscall? (y/n) [timeout in 10 seconds, default=block]: y
[TRACE] openat (257) → TEMPORARILY ALLOWED (added to buffer)
```

Run with verbose dynamic mode:
```bash
./sandbox --verbose --policy ../policies/minimal_policy.json --trace-block-dynamic --exec /bin/cat file.txt
```

This shows every syscall, prompts for unknowns, and builds a runtime allowlist.

### Command-Line Options

```
Usage: ./sandbox --policy <policy.json> --exec <program> [args...] [OPTIONS]

Required:
  --policy <file>         Path to JSON policy file
  --exec <program>        Program to execute in sandbox

Optional:
  --verbose               Enable verbose output
  --trace-block-dynamic   Enable dynamic ptrace-based syscall blocking
```

**Examples:**
```bash
./sandbox --policy base.json --exec /bin/ls
./sandbox --verbose --policy base.json --exec /bin/ls
./sandbox --policy base.json --trace-block-dynamic --exec /bin/ls
./sandbox --verbose --policy base.json --trace-block-dynamic --exec /bin/ls
```

---

## 🧠 How It Works Internally

### Static Mode (Seccomp-BPF)

1. **Sandbox process creation**
   - Parent forks a child.
   - Parent monitors and waits.
   - Child applies seccomp filter and then `execvp()`s the target program.

2. **Seccomp setup**
   - A new filter is created (`SCMP_ACT_KILL` default).
   - Syscalls are resolved by name via `seccomp_syscall_resolve_name()`.
   - Each allowed syscall is added using `seccomp_rule_add()`.

3. **Filter load**
   - The filter is installed using `seccomp_load()`.
   - The kernel enforces the filter for the rest of the child's lifetime.

4. **Execution**
   - The child replaces itself with the user-specified binary.
   - Any disallowed syscall triggers the kernel to block or kill it.

### Dynamic Mode (Ptrace-based) 🆕

1. **Process creation with tracing**
   - Parent forks a child process.
   - Child calls `ptrace(PTRACE_TRACEME)` to enable tracing.
   - Child stops itself with `raise(SIGSTOP)`.
   - Parent sets ptrace options with `PTRACE_SETOPTIONS`.

2. **Syscall interception loop**
   - Parent uses `ptrace(PTRACE_SYSCALL)` to stop at each syscall.
   - For every syscall entry:
     - Read syscall number from `orig_rax` register.
     - Check against base policy (JSON file).
     - Check against dynamic allowlist buffer (in-memory).
     - If unknown: prompt user with 10-second timeout.

3. **User decision handling**
   - **User allows**: Add syscall to dynamic buffer, allow execution.
   - **User blocks**: Replace `orig_rax` with -1, inject EPERM on exit.
   - **Timeout**: Default to block (safe behavior).

4. **Dynamic buffer management**
   - In-memory data structure with auto-growth.
   - Caches user decisions to avoid repeated prompts.
   - Discarded when program exits (no persistent changes).

5. **Syscall blocking mechanism**
   - At syscall entry: Modify registers to invalidate the syscall.
   - At syscall exit: Inject EPERM error code.
   - Program continues execution but syscall appears to fail.

**Key Difference**: Static mode uses kernel enforcement (fast, fixed), while dynamic mode uses userspace interception (slower, flexible).

---

## 🧩 Program Flow

### Static Mode Flow
```
[Start Sandbox] → [Parse CLI args (--policy, --exec)]
                ↓
         [Read & parse JSON policy]
                ↓
         [Fork child process]
                ↓
    ┌───────────┴───────────┐
    ↓                       ↓
 [Child]                [Parent]
    ↓                       ↓
[Create Seccomp filter] [waitpid(child)]
    ↓                       ↓
[Add rules from JSON]   [Report exit/killed status]
    ↓                       ↓
[seccomp_load()]           [End]
    ↓
[execvp(target program)]
```

### Dynamic Mode Flow 
```
[Start Sandbox] → [Parse CLI args (--policy, --exec, --trace-block-dynamic)]
                ↓
         [Read & parse JSON policy]
                ↓
         [Initialize dynamic allowlist buffer]
                ↓
         [Fork child process]
                ↓
    ┌───────────┴───────────────────────┐
    ↓                                   ↓
 [Child]                            [Parent/Tracer]
    ↓                                   ↓
[ptrace(PTRACE_TRACEME)]    [Wait for child to stop]
    ↓                                   ↓
[raise(SIGSTOP)]            [Setup ptrace options]
    ↓                                   ↓
[execvp(target program)]    ┌─→ [ptrace(PTRACE_SYSCALL)]
                            │          ↓
                            │   [Wait for syscall event]
                            │          ↓
                            │   [Read syscall number]
                            │          ↓
                            │   ┌─ In base policy? → Allow
                            │   ├─ In dynamic buffer? → Allow
                            │   └─ Unknown? → Prompt user
                            │          ↓
                            │   ┌─ User allows → Add to buffer, allow
                            │   └─ User blocks → Modify registers, block
                            │          ↓
                            └───[Continue to next syscall]
                                       ↓
                            [Program exits, discard buffer]
```

---

---

## 📊 Evaluation
| Criteria | Description |
|-----------|--------------|
| Functionality | Sandbox runs arbitrary binaries with configurable syscall rules |
| Security | Process confinement via Seccomp-BPF |
| Modularity | Separated JSON, Seccomp, and Process code |
| Extensibility | Support for new features like logging, blocklists |
| Usability | CLI interface + JSON config |

---

## 🔧 Makefile Targets

- `make` or `make all` - Build the sandbox tool
- `make clean` - Remove build artifacts
- `make test` - Run basic tests
- `make install` - Install to /usr/local/bin (requires sudo)
- `make uninstall` - Remove from /usr/local/bin
- `make help` - Show help message



