#include <iostream>
#include <unistd.h>

int addOne(const int number) {
  // 1.) Stop at breakpoint in main.
  // 2.) Fix this code, then run
  // (lldb) hotreload example.cpp
  // (lldb) c
  const int plusOne = number - 1;  // BUG: should be number + 1
  return plusOne;
}
int main() {
  const int number = 0;
  while (true) {
    int result = addOne(number);
    if (result == number + 1) {
      break;
    } else {
      printf("addOne(%d) returned %d (off by %d)\n", number, result, result - (number + 1));
      printf("Fix addOne, save, then run `(lldb) hotreload example.cpp` and continue\n");
    }
    sleep(1);
    // Put a breakpoint here ^^
  }
  printf("Loop exited because addOne returned number + 1\n");
  return 0;
}
