# Examples

This directory contains examples demonstrating LLDB hot reload capabilities.

## [simple/](simple/) - Basic Hot Reload

A single-file example showing the basics of hot reloading a function.

**What it demonstrates:**
- Hot reloading a simple function
- Basic workflow with LLDB
- Compile commands configuration

**Run it:**
```bash
cd simple
make
lldb ./example
(lldb) command script import ../../src/hotreload.py
(lldb) b example.cpp:23
(lldb) run
# Edit example.cpp to fix the bug
(lldb) hotreload example.cpp
(lldb) continue
```

## [inter-file-deps/](inter-file-deps/) - Inter-File Dependencies

Demonstrates hot reloading functions that call other functions across multiple files.

**What it demonstrates:**
- Functions calling functions from other .cpp files
- Using `-rdynamic` for symbol export
- `RTLD_GLOBAL` for runtime symbol resolution

**Run it:**
```bash
cd inter-file-deps
./build.sh
lldb ./myapp
(lldb) command script import ../../src/hotreload.py
(lldb) b main.cpp:27
(lldb) run
# Edit calculator.cpp (change line 8)
(lldb) hotreload calculator.cpp
(lldb) continue
```

**Key requirement:** The binary must be built with `-rdynamic`:
```bash
clang++ -rdynamic -g -O0 main.cpp utils.cpp calculator.cpp -o myapp
```

## Comparison

| Feature | simple | inter-file-deps |
|---------|--------|-----------------|
| Files | 1 .cpp | 3 .cpp files |
| Dependencies | None | Cross-file function calls |
| `-rdynamic` required | No | Yes |

## Next Steps

After trying these examples:
1. Read [../README.md](../README.md) for full documentation
2. Try hot reloading your own projects
3. Check "What Works" and "What Doesn't Work" sections in the main README
