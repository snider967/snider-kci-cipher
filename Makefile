# KCI-20 portable build (GNU make). CMakeLists.txt is the cross-platform alternative.
# Copyright 2026 snider967. Licensed under the Apache License, Version 2.0.

CC      ?= cc
CFLAGS  ?= -O2
WARN    := -std=c11 -Wall -Wextra -Wpedantic -Wconversion -Wshadow -Wstrict-prototypes
CPPFLAGS += -Iinclude
BUILD   ?= build

LIB_SRC := src/core/kci_round.c src/core/kci_deck.c src/core/kci_stream.c src/core/kci_poly1305.c src/core/kci_aead.c src/core/kci_sha256.c src/util/kci_wipe.c
LIB_OBJ := $(LIB_SRC:%.c=$(BUILD)/%.o)
LIB     := $(BUILD)/libkci.a
TEST    := $(BUILD)/test_kci
CLI     := $(BUILD)/kci
CLI_SRC := cli/kci.c cli/platform.c

.PHONY: all test cli-test sanitize vectors clean

all: $(LIB) $(TEST) $(CLI)

$(BUILD)/%.o: %.c include/kci/kci.h src/core/kci_internal.h
	@mkdir -p $(dir $@)
	$(CC) $(CPPFLAGS) $(WARN) $(CFLAGS) -c $< -o $@

$(LIB): $(LIB_OBJ)
	$(AR) rcs $@ $^

$(TEST): tests/test_kci.c tests/kat_vectors.h $(LIB)
	$(CC) $(CPPFLAGS) $(WARN) $(CFLAGS) tests/test_kci.c $(LIB) -o $@

$(CLI): $(CLI_SRC) cli/platform.h $(LIB)
	$(CC) $(CPPFLAGS) $(WARN) $(CFLAGS) $(CLI_SRC) $(LIB) -o $@

test: $(TEST) $(CLI)
	./$(TEST)
	sh tests/cli_test.sh ./$(CLI)

cli-test: $(CLI)
	sh tests/cli_test.sh ./$(CLI)

# AddressSanitizer + UndefinedBehaviorSanitizer build in its own directory
sanitize:
	$(MAKE) BUILD=build-san CFLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all" \
	        LDFLAGS="-fsanitize=address,undefined" test

# Regenerate tests/kat_vectors.h from the Python reference sketch
vectors:
	python3 -I tools/gen_vectors.py

clean:
	rm -rf build build-san
