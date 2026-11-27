/* Platform layer for the kci CLI. Linux/BSD/macOS via POSIX; Windows via the Win32 API (untested so far).
 * Copyright 2026 snider967. Licensed under the Apache License, Version 2.0. */
#if !defined(_WIN32)
#define _DEFAULT_SOURCE 1      /* getrandom, termios, fdopen, open flags under -std=c11 */
#define _DARWIN_C_SOURCE 1
#endif

#include "platform.h"

#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <bcrypt.h>
#include <conio.h>
#include <io.h>
#include <fcntl.h>
#include <sys/stat.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif

int plat_random(uint8_t *buf, size_t n)
{
#if defined(_WIN32)
    return BCryptGenRandom(NULL, buf, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0 ? 0 : -1;
#elif defined(__linux__)
    while (n > 0) {
        ssize_t r = getrandom(buf, n, 0);
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        buf += r; n -= (size_t)r;
    }
    return 0;
#else   /* macOS, *BSD */
    arc4random_buf(buf, n);
    return 0;
#endif
}

int plat_read_password(const char *prompt, char *buf, size_t cap)
{
    size_t len = 0;
#if defined(_WIN32)
    fputs(prompt, stderr); fflush(stderr);
    for (;;) {
        int ch = _getch();
        if (ch == '\r' || ch == '\n') break;
        if (ch == 3) return -1;                         /* Ctrl-C */
        if (ch == '\b') { if (len) len--; continue; }
        if (len + 1 >= cap) return -1;
        buf[len++] = (char)ch;
    }
    fputs("\n", stderr);
#else
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) return -1;
    int fd = fileno(tty);
    struct termios old, quiet;
    if (tcgetattr(fd, &old) != 0) { fclose(tty); return -1; }
    quiet = old;
    quiet.c_lflag &= (tcflag_t)~(ECHO | ECHONL);
    fputs(prompt, tty); fflush(tty);
    tcsetattr(fd, TCSAFLUSH, &quiet);
    int ok = 1, ch;
    while ((ch = fgetc(tty)) != EOF && ch != '\n') {
        if (len + 1 >= cap) { ok = 0; continue; }       /* keep reading so the line is consumed */
        buf[len++] = (char)ch;
    }
    tcsetattr(fd, TCSAFLUSH, &old);
    fputs("\n", tty);
    fclose(tty);
    if (!ok) { memset(buf, 0, cap); return -1; }
#endif
    if (len && buf[len - 1] == '\r') len--;
    buf[len] = '\0';
    return (int)len;
}

FILE *plat_create_private(const char *path)
{
#if defined(_WIN32)
    int fd = _open(path, _O_WRONLY | _O_CREAT | _O_EXCL | _O_BINARY, _S_IREAD | _S_IWRITE);
    return fd < 0 ? NULL : _fdopen(fd, "wb");
#else
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) return NULL;
    FILE *f = fdopen(fd, "wb");
    if (!f) close(fd);
    return f;
#endif
}

int plat_exists(const char *path)
{
    FILE *f = fopen(path, "rb");
    if (f) { fclose(f); return 1; }
    return 0;
}

int plat_rename(const char *src, const char *dst)
{
#if defined(_WIN32)
    return MoveFileExA(src, dst, MOVEFILE_REPLACE_EXISTING) ? 0 : -1;
#else
    return rename(src, dst);
#endif
}
