CC := gcc
CFLAGS := -Wall -O2
LDLIBS := -lz

TARGET := copyfail
SRC := copyfail.c

.PHONY: all clean clean_page_cache

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	rm -f $(TARGET)

clean_page_cache:
	sudo sh -c 'echo 3 > /proc/sys/vm/drop_caches'
