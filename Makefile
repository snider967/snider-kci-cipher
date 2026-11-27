# KCI-20 portable build (GNU make). CMakeLists.txt is the cross-platform alternative.
# Copyright 2026 snider967. Licensed under the Apache License, Version 2.0.

CC      ?= cc
CFLAGS  ?= -O2
WARN    := -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
CPPFLAGS += -Iinclude
BUILD   ?= build

LIB_SRC := src/core/kci_round.c src/core/kci_deck.c src/core/kci_stream.c src/util/kci_wipe.c
LIB_OBJ := $(LIB_SRC:%.c=$(BUILD)/%.o)
LIB     := $(BUILD)/libkci.a
TEST    := $(BUILD)/test_kci

.PHONY: all test sanitize vectors clean

all: $(LIB) $(TEST)

$(BUILD)/%.o: %.c include/kci/kci.h src/core/kci_internal.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(WARN) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJ)
	$(AR) rcs $@ $^

$(TEST): tests/test_kci.c tests/kat_vectors.h $(LIB)
	$(CC) $(CPPFLAGS) $(WARN) $(CFLAGS) tests/test_kci.c $(LIB) -o $@

test: $(TEST)
	./$(TEST)

# AddressSanitizer + UndefinedBehaviorSanitizer build in its own directory
sanitize:
	$(MAKE) BUILD=build-san CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" \
	        LDFLAGS="-fsanitize=address,undefined" test

# Regenerate tests/kat_vectors.h from the Python reference sketch
vectors:
	python3 -I tools/gen_vectors.py

clean:
	rm -rf build build-san
