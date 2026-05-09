CC := gcc
CFLAGS := -Wall -O2
LDLIBS :=

SRC_DIR := src
DIST_DIR := dist
TARGET := $(DIST_DIR)/copyfail
SRC := $(SRC_DIR)/copyfail.c
DROP_CACHE_TOOL := $(DIST_DIR)/drop_file_cache
DROP_CACHE_SRC := $(SRC_DIR)/drop_file_cache.c

.PHONY: all clean drop_input_cache check_input_file

all: $(TARGET) $(DROP_CACHE_TOOL)

$(TARGET): $(SRC)
	mkdir -p $(DIST_DIR)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

$(DROP_CACHE_TOOL): $(DROP_CACHE_SRC)
	mkdir -p $(DIST_DIR)
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f $(TARGET) $(DROP_CACHE_TOOL)

check_input_file:
	@if [ -z "$(INPUT_FILE)" ]; then \
		echo "usage: make drop_input_cache INPUT_FILE=<path>"; \
		exit 1; \
	fi

drop_input_cache: $(DROP_CACHE_TOOL) check_input_file
	./$(DROP_CACHE_TOOL) $(INPUT_FILE)
