/* Platform layer for the kci CLI: OS randomness, password prompt, private files.
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#ifndef KCI_CLI_PLATFORM_H
#define KCI_CLI_PLATFORM_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Fill buf with cryptographically secure random bytes from the OS. Returns 0 on success. */
int plat_random(uint8_t *buf, size_t n);

/* Prompt on the terminal and read a line with echo off. Returns length, or -1 (no terminal / error / too long). */
int plat_read_password(const char *prompt, char *buf, size_t cap);

/* Create a new file that only the user can read (0600 on POSIX), failing if it already exists. */
FILE *plat_create_private(const char *path);

/* 1 if path exists. */
int plat_exists(const char *path);

/* Replace dst with src (atomic on POSIX). Returns 0 on success. */
int plat_rename(const char *src, const char *dst);

#endif
