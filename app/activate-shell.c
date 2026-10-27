#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define TOKEN_FILE "/tmp/node2shell-shell.enabled"
#define TOKEN_BYTES 32

static int write_all(int fd, const char *buffer, size_t length) {
    while (length > 0) {
        ssize_t written = write(fd, buffer, length);
        if (written < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        buffer += written;
        length -= (size_t)written;
    }
    return 0;
}

static int read_all(int fd, unsigned char *buffer, size_t length) {
    while (length > 0) {
        ssize_t received = read(fd, buffer, length);
        if (received < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (received == 0) return -1;
        buffer += received;
        length -= (size_t)received;
    }
    return 0;
}

int main(void) {
    const char *variant = getenv("LAB_VARIANT");
    if (variant == NULL || strcmp(variant, "vulnerable") != 0) {
        dprintf(STDERR_FILENO, "shell activation is disabled on this control\n");
        return 1;
    }

    unsigned char random_bytes[TOKEN_BYTES];
    int random_fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (random_fd < 0 || read_all(random_fd, random_bytes, sizeof(random_bytes)) < 0) {
        dprintf(STDERR_FILENO, "unable to generate shell token\n");
        if (random_fd >= 0) close(random_fd);
        return 1;
    }
    close(random_fd);

    static const char hex[] = "0123456789abcdef";
    char token[TOKEN_BYTES * 2 + 2];
    for (size_t i = 0; i < TOKEN_BYTES; i++) {
        token[i * 2] = hex[random_bytes[i] >> 4];
        token[i * 2 + 1] = hex[random_bytes[i] & 0x0f];
    }
    token[TOKEN_BYTES * 2] = '\n';
    token[TOKEN_BYTES * 2 + 1] = '\0';

    int token_fd = open(TOKEN_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (token_fd < 0 || write_all(token_fd, token, TOKEN_BYTES * 2 + 1) < 0) {
        dprintf(STDERR_FILENO, "unable to write shell token\n");
        if (token_fd >= 0) close(token_fd);
        return 1;
    }
    fsync(token_fd);
    close(token_fd);

    dprintf(STDOUT_FILENO, "NODE2SHELL_SHELL_TOKEN=%.*s\n", TOKEN_BYTES * 2, token);
    return 0;
}
