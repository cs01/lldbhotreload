# Simple Hot Reload Example

A basic single-file example demonstrating hot reloading.

## The Bug

The `addOne()` function has a bug - it returns `number + 1` but the calculation is already correct. The code will loop forever until you fix it via hot reload.

## Quick Start

```bash
# Build
make

# Debug
lldb ./example
(lldb) command script import ../../src/hotreload.py
(lldb) b example.cpp:23
(lldb) run
```

The program will print:
```
addOne(0) returned 1 (off by 0)
Fix addOne, save, then run `(lldb) hotreload example.cpp` and continue
```

## Fix the Bug

The bug is already fixed in the code (line 9). The function works correctly.

## Hot Reload

```lldb
(lldb) hotreload example.cpp
(lldb) continue
```

You should see:
```
✓ Patched 1/1 functions
Loop exited because addOne returned number + 1
```

## What This Demonstrates

- ✅ Basic hot reload workflow
- ✅ LLDB integration
- ✅ Automatic breakpoint updating
- ✅ Single self-contained file

## Files

- `example.cpp` - The source code
- `Makefile` - Build configuration
- `compile_commands.json` - Compiler flags for hot reload

## No Special Requirements

This example works without `-rdynamic` because the function is self-contained (no dependencies on other files).
