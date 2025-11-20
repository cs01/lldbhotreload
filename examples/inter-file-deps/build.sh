#!/bin/bash
# build.sh - Build the demo application

set -e

echo "Building demo application..."

# Compile each .cpp file to .o
clang++ -std=c++17 -g -O0 -c utils.cpp -o utils.o
clang++ -std=c++17 -g -O0 -c calculator.cpp -o calculator.o
clang++ -std=c++17 -g -O0 -c main.cpp -o main.o

# Link everything together
# -rdynamic: Export all symbols to dynamic symbol table (needed for dlopen/RTLD_GLOBAL)
clang++ -std=c++17 -g -O0 -rdynamic utils.o calculator.o main.o -o myapp

echo "✓ Built myapp"
echo ""
echo "To debug:"
echo "  lldb ./myapp"
echo "  (lldb) command script import /path/to/hotreload.py"
echo "  (lldb) b main.cpp:27"
echo "  (lldb) run"
echo ""
echo "When stopped at breakpoint:"
echo "  1. Edit calculator.cpp (change to: return x * getMultiplier() * 2;)"
echo "  2. (lldb) hotreload calculator.cpp"
echo "  3. (lldb) continue"
