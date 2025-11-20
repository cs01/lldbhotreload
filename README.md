# LLDB Hot Reload for C++

Edit code while debugging and see changes immediately without a restart.

## Quick Start

Download hotreload.py:
```
curl -O  https://raw.githubusercontent.com/cs01/lldbhotreload/main/src/hotreload.py
```

```bash
$ lldb ./your_program
(lldb) command script import hotreload.py
(lldb) b your_file.cpp:50
(lldb) run

# Edit your_file.cpp in your editor and save
(lldb) hotreload your_file.cpp
(lldb) continue
```

You can also add `command script import /path/to/hotreload.py` to your `~/.lldbinit` so the `hotreload` command is always available.

Changes apply immediately!

## Examples

See [examples/](examples/) for complete working demos:
- **[simple/](examples/simple/)** - Basic single-file hot reload
- **[inter-file-deps/](examples/inter-file-deps/)** - Hot reload functions calling other files

## Requirements

- Linux x86_64
- LLDB
- Clang

```bash
# When building your program:
clang++ -rdynamic -g -O0 main.cpp utils.cpp -o myapp
```

The `-rdynamic` flag exports symbols so hot-reloaded code can find functions from your original binary.

## API

### `hotreload <path> [flags...]`
Recompile and patch all functions in a source file.

```bash
hotreload your_file.cpp
hotreload src/math.cpp -std=c++20 -I./include
hotreload lib/utils.cpp -O2 -DDEBUG
```

Compiler flags precedence:
1. Explicit flags - If you pass flags on command line, they're used
2. compile_commands.json - Automatically searches for and loads flags from compilation database
3. Default flags - Uses `-std=c++17 -O0 -g` if no other source is found

## What Works
- Free functions (functions not inside classes) with standard return types (`int`, `float`, `double`, `void`)
- Pointers and references
- STL types like `std::vector`, `std::string`

## What Doesn't Work

* On-stack functions: Functions currently on the call stack cannot be patched. Set a breakpoint outside the function to reload it.
* Class Methods
* Templates
* Function signature changes

Compilation errors will show if you try to hot reload any of the above.

## Example session
```
hotreload example.cpp
Hot reloading: example.cpp
  Found 1 functions: ['addOne(int)']
  Compiling .so...
  → (int)dlclose((void*)0x417300)
  → dlclose() succeeded
  → g++ -std=c++17 -g -O0 -fPIC -shared -o /tmp/lldb_hotreload/hotreload_example_de7d20e4.so /tmp/lldb_hotreload/hotreload_example_de7d20e4.cpp
  Compiled to /tmp/lldb_hotreload/hotreload_example_de7d20e4.so
  → (void*)dlopen("/tmp/lldb_hotreload/hotreload_example_de7d20e4.so", 2 | 256)
  → dlopen() returned handle 0x417300
  → LLDB auto-detected module: hotreload_example_de7d20e4.so
  Processing addOne(int) @ 0x401176
  → ((void*(*)())dlsym((void*)0x417300, "__addOne_hotreload_de7d20e4_ptr"))())
  → Resolved addOne(int) to 0x7ffff7fb5169
  Re-patching addOne(int): 0x401176 → 0x7ffff7fb5169
  → WriteMemory(0x401176, 21 bytes)
     [48 b8 69 51 fb f7 ff 7f 00 00 ff e0] + 9 NOPs
     Disassembly: movabsq $0x7ffff7fb5169, %rax; jmp *%rax; nop×9
  Deleted 1 old breakpoint(s) from previous hot reloads
✓ Patched 1/1 functions
  Auto-breakpoint: addOne(int) at hotreload_example_de7d20e4.cpp:23 (addr 0x7ffff7fb5169)
============================================================
  ✓ Created 1 auto-breakpoint(s) in hot-reloaded code
  Next 'continue' will hit breakpoints in new code!
  Manual breakpoints: b /tmp/lldb_hotreload/hotreload_example_de7d20e4.cpp:<line>
============================================================
```

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Edit code.cpp and save                                      │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. (lldb) hotreload code.cpp                                    │
│    → Compile to code_hash123.so with renamed functions          │
│    → dlopen() loads .so into running process                    │
│    → dlsym() finds new function addresses                       │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. Patch original function with JMP to new code                 │
│                                                                 │
│    Original (0x1000):        After patch:                       │
│    ┌──────────────┐          ┌──────────────┐                  │
│    │ push rbp     │          │ jmp 0x7f...  │─┐                │
│    │ mov rbp, rsp │          │ nop nop ...  │ │                │
│    │ ...          │          │ ...          │ │                │
│    └──────────────┘          └──────────────┘ │                │
│                                                │                │
│    New code (0x7f...):                         │                │
│    ┌──────────────┐          ◀────────────────┘                │
│    │ push rbp     │                                             │
│    │ mov rbp, rsp │                                             │
│    │ NEW CODE!    │                                             │
│    │ ret          │                                             │
│    └──────────────┘                                             │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. (lldb) continue                                              │
│    → Calls to old address execute new code                      │
│    → Breakpoints auto-updated to new code                       │
└─────────────────────────────────────────────────────────────────┘
```

We load new code via `dlopen()`, then overwrite the old function's first bytes with a JMP instruction. Callers never know — they jump to the old address, hit the JMP, and bounce to the new implementation.

### Background
On x86-64 Linux, functions are just sequences of machine code at memory addresses. When you call a function, the CPU jumps to that address and executes. The `dlopen()` API allows a running process to load new shared libraries at runtime.

Why LLDB? LLDB's JIT expression evaluator (`frame.EvaluateExpression()`) makes this possible. It lets us execute arbitrary C code (like `dlopen()`, `dlsym()`) inside the debugged process without manually injecting shellcode. LLDB also provides access to DWARF debug info, process memory (`WriteMemory()`), and stack introspection.

### 1. DWARF Analysis
Uses LLDB's debug information to discover all functions compiled from the source file.

### 2. Compilation with Function Renaming and Wrappers
The system compiles your modified code.

```cpp
// Your original function (mangled name: _Z9calculatei)
int calculate(int x) { return x * 2; }
```

**Step 1:** Rename with content hash:
```cpp
int calculate_hotreload_12ab34cd(int x) { return x * 2; }
```

**Step 2:** Create inline wrapper for intra-file calls:
```cpp
inline int calculate(int x) {
    return calculate_hotreload_12ab34cd(x);
}
```

**Step 3:** Add `extern "C"` pointer getter for `dlsym()`:
```cpp
extern "C" {
void* __calculate_hotreload_12ab34cd_ptr() {
    return (void*)&calculate_hotreload_12ab34cd;
}
}
```

C++ name mangling makes function names unpredictable. The `extern "C"` pointer getters give us predictable names for `dlsym()` lookup, while inline wrappers preserve function calls between hot-reloaded functions.

### 3. Dynamic Loading
- Calls `dlopen()` via `frame.EvaluateExpression()` to load the `.so`
- Adds module to LLDB with `AddModule()` for debug symbols
- Uses `dlsym()` to get the pointer-getter, then calls it for the actual address

On subsequent reloads, we `dlclose()` the old .so and load a new one with a different hash, re-patching the same original address.

### 4. Runtime Patching
DWARF provides the exact memory address where each old function starts. The system writes a JMP instruction at that address using lldb's `process.WriteMemory()`, replacing the function's prologue with a trampoline to the new code.

### 5. Breakpoint Refresh
After patching, the system automatically refreshes breakpoints. It deletes old breakpoints in patched functions and recreates them at the same source lines, which LLDB resolves to the new module's addresses.
