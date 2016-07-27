/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2015 Red Hat, Inc.
 * Author: Nathaniel McCallum <npmccallum@redhat.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include "pcmd.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static bool
mkcmd(const char *argv0, const char *pin, char out[], int len)
{
    char *delim = NULL;

    if (snprintf(out, len, "%s", argv0) > len)
        return false;

    delim = strrchr(out, '/');
    if (!delim)
        delim = out;

    return snprintf(delim, len, "/clevis-pin-%s", pin) <= len;
}

enum {
    PIPE_RD = 0,
    PIPE_WR = 1
};

uint8_t *
pcmd(const char *argv0, const char *pin, const char *cmd, const char *cfg,
     const uint8_t *in, size_t inl, size_t *outl)
{
    char path[PATH_MAX] = {};
    char *args[] = { path, (char *) cmd, (char *) cfg, NULL };
    int dump[2] = { -1, -1 };
    int load[2] = { -1, -1 };
    uint8_t buf[512] = {};
    uint8_t *out = NULL;
    ssize_t wr = 0;
    pid_t pid = 0;
    int wst = 0;

    if (!mkcmd(argv0, pin, path, sizeof(path)))
        return NULL;

    if (pipe2(dump, O_CLOEXEC) < 0)
        goto error;

    if (pipe2(load, O_CLOEXEC) < 0)
        goto error;

    pid = fork();
    if (pid < 0)
        goto error;

    if (pid == 0) {
        if (dup2(dump[PIPE_RD], STDIN_FILENO) < 0 ||
            dup2(load[PIPE_WR], STDOUT_FILENO) < 0)
            exit(EXIT_FAILURE);

        execvp(args[0], args);
        exit(EXIT_FAILURE);
    }

    for (const uint8_t *tmp = in; inl > 0; tmp += wr, inl -= wr) {
        wr = write(dump[PIPE_WR], tmp, inl);
        if (wr < 0)
            goto error;
    }

    close(dump[PIPE_RD]);
    close(dump[PIPE_WR]);
    close(load[PIPE_WR]);

    *outl = 0;
    while ((wr = read(load[PIPE_RD], buf, sizeof(buf))) > 0) {
        uint8_t *tmp = NULL;

        tmp = realloc(out, *outl + wr);
        if (!tmp) {
            kill(pid, SIGTERM);
            break;
        }

        out = tmp;
        memmove(&out[*outl], buf, wr);
        *outl += wr;
    }

    close(load[PIPE_RD]);

    if (waitpid(pid, &wst, 0) == pid &&
        WIFEXITED(wst) &&
        WEXITSTATUS(wst) == 0)
        return out;

    if (out)
        memset(out, 0, *outl);

    free(out);
    return NULL;

error:
    close(dump[PIPE_RD]);
    close(dump[PIPE_WR]);
    close(load[PIPE_RD]);
    close(load[PIPE_WR]);

    if (pid > 0) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }

    return NULL;
}

