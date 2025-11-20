// calculator.cpp - The file we want to hot reload
#include "utils.h"

int calculate(int x) {
  const int a = 100;
  // BUG: We want to multiply by 20, not 10!
  // FIX: Change getMultiplier() to return 20 in utils.cpp
  // OR: Change this to: return x * getMultiplier() * 2;
  return x * getMultiplier() * a;
}

int complexCalculation(int x, int y) {
  // This function uses BOTH dependencies
  return (x * getMultiplier()) + (y + getAdder());
}
