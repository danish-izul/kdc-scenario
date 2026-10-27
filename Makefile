CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Wshadow
CXXFLAGS += -Iinclude
LDFLAGS  ?=

BUILD   := build
LIB_SRC := src/bytes.cpp src/io.cpp src/trace.cpp src/sha256.cpp src/aes256.cpp src/cbc.cpp src/net.cpp src/ns.cpp
LIB_OBJ := $(LIB_SRC:src/%.cpp=$(BUILD)/%.o)
PROGS   := $(BUILD)/kdc $(BUILD)/alice $(BUILD)/bob

.PHONY: all static test clean

all: $(PROGS) $(BUILD)/kat

static:
	$(MAKE) clean
	$(MAKE) all LDFLAGS=-static

$(BUILD)/%.o: src/%.cpp $(wildcard include/*.hpp) | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/kdc $(BUILD)/alice $(BUILD)/bob: $(BUILD)/%: $(BUILD)/%.o $(LIB_OBJ)
	$(CXX) $(CXXFLAGS) $^ -o $@ $(LDFLAGS)

$(BUILD)/kat: tests/kat.cpp $(LIB_OBJ) $(wildcard include/*.hpp) | $(BUILD)
	$(CXX) $(CXXFLAGS) tests/kat.cpp $(LIB_OBJ) -o $@ $(LDFLAGS)

$(BUILD):
	@mkdir -p $(BUILD)

test: $(BUILD)/kat
	./$(BUILD)/kat

clean:
	rm -rf $(BUILD)
