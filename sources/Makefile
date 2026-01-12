# =========================
# Compiler and flags
# =========================
CC = gcc
CFLAGS = -Wall -Wextra -O2

# =========================
# Include directories
# =========================
# Top-level include + all "include" folders under src/
INCLUDE_DIRS := $(shell find include src -type d -name include)
CFLAGS += $(foreach dir,$(INCLUDE_DIRS),-I$(dir))

# =========================
# Directories
# =========================
SRC_DIR = src
TEST_DIR = tests
OBJ_DIR = build

# =========================
# Source and object files
# =========================
SRC_FILES := $(shell find $(SRC_DIR) -name '*.c')
OBJ_FILES := $(patsubst $(SRC_DIR)/%.c,$(OBJ_DIR)/%.o,$(SRC_FILES))

TEST_FILES := $(wildcard $(TEST_DIR)/*.c)
TEST_OBJ_FILES := $(patsubst $(TEST_DIR)/%.c,$(OBJ_DIR)/tests/%.o,$(TEST_FILES))

# =========================
# Output
# =========================
LIB_NAME = libhmac_aead.a
TEST_BIN = aead_app

# =========================
# Default target
# =========================
all: $(OBJ_DIR) $(LIB_NAME) $(TEST_BIN)

# =========================
# Create build directories
# =========================
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# =========================
# Compile src .c -> .o
# =========================
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# =========================
# Compile test .c -> .o
# =========================
$(OBJ_DIR)/tests/%.o: $(TEST_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# =========================
# Archive library
# =========================
$(LIB_NAME): $(OBJ_FILES)
	ar rcs $@ $^

# =========================
# Build test executable
# =========================
$(TEST_BIN): $(LIB_NAME) $(TEST_OBJ_FILES)
	$(CC) $(CFLAGS) -o $@ $(TEST_OBJ_FILES) -L. -lhmac_aead

# =========================
# Clean
# =========================
clean:
	rm -rf $(OBJ_DIR) $(LIB_NAME) $(TEST_BIN)

.PHONY: all clean
