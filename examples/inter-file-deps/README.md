# Inter-File Dependencies Example

Demonstrates hot reloading functions that call other functions across multiple files.

## The Setup

Three files work together:
- `utils.cpp` - Helper functions (`getMultiplier()`, `getAdder()`)
- `calculator.cpp` - **The file we'll hot reload** (calls functions from utils.cpp)
- `main.cpp` - Main program loop

## The Bug

`calculator.cpp` line 8 should multiply by 20, but only multiplies by 10.

```cpp
// Current (wrong):
return x * getMultiplier();  // getMultiplier() returns 10, so 5 * 10 = 50

// Fix:
return x * getMultiplier() * 2;  // 5 * 10 * 2 = 100 ✓
```

## Quick Start

```bash
# Build (note the -rdynamic flag!)
./build.sh

# Debug
lldb ./myapp
(lldb) command script import ../../src/hotreload.py
(lldb) b main.cpp:27
(lldb) run
```

The program will print:
```
calculate(5) = 50 (expected: 100)
Fix the bug and run: (lldb) hotreload calculator.cpp
```

## Fix the Bug

Edit `calculator.cpp` line 8:
```cpp
return x * getMultiplier() * 2;  // Add the * 2
```

Save the file.

## Hot Reload

```lldb
(lldb) hotreload calculator.cpp
(lldb) continue
```

You should see:
```
✓ Patched 2/2 functions
calculate(5) = 100 (expected: 100)
SUCCESS! Hot reload worked!
```

## What This Demonstrates

- ✅ **Inter-file dependencies** - `calculator.cpp` calls `getMultiplier()` from `utils.cpp`
- ✅ **Runtime symbol resolution** - Uses `RTLD_GLOBAL` + `-rdynamic`
- ✅ **Multiple functions** - Hot reloads both `calculate()` and `complexCalculation()`

## Key Requirement: `-rdynamic`

This example **requires** the binary to be built with `-rdynamic`:

```bash
clang++ -rdynamic -g -O0 main.cpp utils.cpp calculator.cpp -o myapp
```

**Why?** The `-rdynamic` flag exports symbols to the dynamic symbol table so the hot-reloaded `.so` can find functions from the original binary at runtime.

Without it, you'll see:
```
✗ dlopen() failed: undefined symbol: _Z13getMultiplierv

⚠ HINT: Your binary may not have been built with -rdynamic
```

## Files

- `main.cpp` - Main program
- `calculator.cpp` - **Hot reload this file**
- `utils.cpp` - Helper functions
- `utils.h` - Header file
- `build.sh` - Build script (includes `-rdynamic`)
- `compile_commands.json` - Compiler flags
