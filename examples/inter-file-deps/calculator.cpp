// calculator.cpp - The file we want to hot reload
#include "utils.h"

int calculate(int x) {
  // BUG: Should multiply by 20, not 10
  return x * getMultiplier();
}

int complexCalculation(int x, int y) {
  return (x * getMultiplier()) + (y + getAdder());
}
