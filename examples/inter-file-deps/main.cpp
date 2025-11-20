// main.cpp
#include <iostream>
#include <unistd.h>

// Functions from calculator.cpp
extern int calculate(int);
extern int complexCalculation(int, int);

int main() {
    std::cout << "Starting program. Stop at breakpoint to hot reload calculator.cpp\n";

    int count = 0;
    while (true) {
        int result = calculate(5);
        int complex_result = complexCalculation(3, 7);

        std::cout << "Iteration " << count++ << ":\n";
        std::cout << "  calculate(5) = " << result << " (expected: 100)\n";
        std::cout << "  complexCalculation(3, 7) = " << complex_result << "\n";

        if (result == 100) {
            std::cout << "SUCCESS! Hot reload worked!\n";
            break;
        } else {
            std::cout << "  Fix the bug and run: (lldb) hotreload calculator.cpp\n";
        }

        sleep(2);
        // Set breakpoint here: b main.cpp:27
    }

    return 0;
}
