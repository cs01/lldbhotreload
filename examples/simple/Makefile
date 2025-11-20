CXX ?= clang++
CXXFLAGS = -std=c++17 -g -O0
TARGET = example
SOURCE = example.cpp

.PHONY: all clean compile_commands.json

all: $(TARGET) compile_commands.json

$(TARGET): $(SOURCE)
	@$(CXX) $(CXXFLAGS) $< -o $@
	@echo "✓ Built $(TARGET)"

compile_commands.json: $(SOURCE)
	@echo '[' > $@
	@echo '  {' >> $@
	@echo '    "directory": ".",' >> $@
	@echo '    "command": "$(CXX) $(CXXFLAGS) -c $(SOURCE)",' >> $@
	@echo '    "file": "$(SOURCE)"' >> $@
	@echo '  }' >> $@
	@echo ']' >> $@
	@echo "✓ Generated compile_commands.json"

clean:
	rm -f $(TARGET) compile_commands.json
