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

#include "sss_alg.h"

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

enum {
    PIPE_RD = 0,
    PIPE_WR = 1
};

static uint8_t *
readall(FILE *file, size_t *len)
{
    uint8_t *out = NULL;

    *len = 0;

    while (true) {
        uint8_t *tmp = NULL;
        size_t r = 0;

        tmp = realloc(out, *len + 16);
        if (!tmp)
            break;
        out = tmp;

        r = fread(&out[*len], 1, 16, file);
        *len += r;
        if (r < 16) {
            if (ferror(file) || *len == 0)
                break;
            if (feof(file))
                return out;
        }
    }

    if (out)
        memset(out, 0, *len);

    free(out);
    return NULL;
}

static FILE *
call(char *const argv[], void *buf, size_t len, pid_t *pid)
{
    int dump[2] = { -1, -1 };
    int load[2] = { -1, -1 };
    FILE *out = NULL;
    ssize_t wr = 0;

    *pid = 0;

    if (pipe(dump) < 0)
        goto error;

    if (pipe(load) < 0)
        goto error;

    *pid = fork();
    if (*pid < 0)
        goto error;

    if (*pid == 0) {
        if (dup2(dump[PIPE_RD], STDIN_FILENO) < 0 ||
            dup2(load[PIPE_WR], STDOUT_FILENO) < 0)
            exit(EXIT_FAILURE);

        if (close(dump[PIPE_RD]) < 0 ||
            close(dump[PIPE_WR]) < 0 ||
            close(load[PIPE_RD]) < 0 ||
            close(load[PIPE_WR]) < 0)
            exit(EXIT_FAILURE);

        execv(argv[0], argv);
        exit(EXIT_FAILURE);
    }

    for (uint8_t *tmp = buf; len > 0; tmp += wr, len -= wr) {
        wr = write(dump[PIPE_WR], tmp, len);
        if (wr < 0)
            goto error;
    }

    out = fdopen(load[PIPE_RD], "r");
    if (!out)
        goto error;

    close(dump[PIPE_RD]);
    close(dump[PIPE_WR]);
    close(load[PIPE_WR]);
    return out;

error:
    close(dump[PIPE_RD]);
    close(dump[PIPE_WR]);
    close(load[PIPE_RD]);
    close(load[PIPE_WR]);

    if (*pid > 0) {
        kill(*pid, SIGTERM);
        waitpid(*pid, NULL, 0);
        *pid = 0;
    }

    return NULL;
}

static int
encrypt(int argc, char *argv[])
{
    const char *key = NULL;
    json_t *pins = NULL;
    json_t *cfg = NULL;
    json_t *sss = NULL;
    json_t *val = NULL;
    uint8_t *in = NULL;
    json_int_t t = 1;
    size_t inl = 0;

    in = readall(stdin, &inl);
    if (!in) {
        fprintf(stderr, "Error reading input!\n");
        return EXIT_FAILURE;
    }

    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Error parsing config!\n");
        goto egress;
    }

    if (json_unpack(cfg, "{s?I,s:o}", "t", &t, "pins", &pins) != 0) {
        fprintf(stderr, "Config missing 'pins' attribute!\n");
        goto egress;
    }

    if (t < 1 || t > (json_int_t) json_object_size(pins)) {
        fprintf(stderr, "Invalid threshold (required: 1 <= %lld <= %zu)!\n",
                t, json_object_size(pins));
        goto egress;
    }

    sss = sss_generate(32, t);
    if (!sss) {
        fprintf(stderr, "Generating SSS!\n");
        goto egress;
    }

    /*
    json_object_foreach(pins, key, val) {
        json_t *pin = NULL;
        size_t i = 0;

        if (json_is_object(val))
            val = json_pack("[O]", val);
        else if (json_is_array(val))
            val = json_incref(val);
        else
            goto egress;

        json_array_foreach(val, i, pin) {
            char *args[] = { (char *) key, "encrypt", NULL, NULL };
            uint8_t *pnt = NULL;
            json_t *jwe = NULL;
            FILE *pipe = NULL;
            size_t pntl = 0;
            pid_t pid = 0;

            argv[2] = json_dumps(pin, JSON_SORT_KEYS | JSON_COMPACT);
            if (!argv[2])
                goto egress;

            pnt = sss_point(sss, &pntl);
            if (!pnt)
                goto egress;

            pipe = call(args, pnt, pntl, &pid);
            if (pipe < 0)
                goto egress;

            jwe = json_loadf(pipe, 0, NULL);
            fclose(pipe);
            waitpid(pid, NULL, 0);
            if (!jwe)
                goto egress;

            if (json_array_append(json_object_get(sss, "pins"), jwe)
        }

    }*/

    jwk = json_pack(
}

static int
decrypt(int argc, char *argv[])
{
}

int
main(int argc, char *argv[])
{
    if (argc == 3 && strcmp(argv[1], "encrypt") == 0)
        return encrypt(argc, argv);

    if (argc == 2 && strcmp(argv[1], "decrypt") == 0)
        return decrypt(argc, argv);

    fprintf(stderr, "Usage: %s encrypt CONFIG\n", argv[0]);
    fprintf(stderr, "   or: %s decrypt\n", argv[0]);
    return EXIT_FAILURE;
}
