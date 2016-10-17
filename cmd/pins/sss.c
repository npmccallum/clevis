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
#include "libsss.h"

#include <jose/b64.h>
#include <jose/jwe.h>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <libgen.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

static bool
mkcmd(const char *name, char *out, size_t len)
{
    char tmp[PATH_MAX] = {};

    if (readlink("/proc/self/exe", tmp, sizeof(tmp) - 1) < 0)
        return false;

    if (snprintf(out, len, "%s/%s", dirname(tmp), name) < 0)
        return false;

    return true;
}

static FILE *
call(char *const argv[], void *buf, size_t len, pid_t *pid)
{
    int dump[2] = { -1, -1 };
    int load[2] = { -1, -1 };
    FILE *out = NULL;
    ssize_t wr = 0;

    *pid = 0;

    if (pipe2(dump, O_CLOEXEC) < 0)
        goto error;

    if (pipe2(load, O_CLOEXEC) < 0)
        goto error;

    *pid = fork();
    if (*pid < 0)
        goto error;

    if (*pid == 0) {
        if (dup2(dump[PIPE_RD], STDIN_FILENO) < 0 ||
            dup2(load[PIPE_WR], STDOUT_FILENO) < 0)
            exit(EXIT_FAILURE);

        execvp(argv[0], argv);
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

static json_int_t
npins(json_t *pins)
{
    const char *key = NULL;
    json_t *val = NULL;
    json_int_t n = 0;

    json_object_foreach(pins, key, val) {
        if (json_is_object(val))
            n++;
        else if (json_is_array(val))
            n += json_array_size(val);
    }

    return n;
}

static int
cmd_encrypt(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    const char *key = NULL;
    json_t *pins = NULL;
    json_t *cfg = NULL;
    json_t *cek = NULL;
    json_t *jwe = NULL;
    json_t *sss = NULL;
    json_t *val = NULL;
    uint8_t *pt = NULL;
    json_int_t t = 1;
    size_t ptl = 0;

    /* Read all plaintext. */
    pt = readall(stdin, &ptl);
    if (!pt) {
        fprintf(stderr, "Error reading input!\n");
        return EXIT_FAILURE;
    }

    /* Parse configuration. */
    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Error parsing config!\n");
        goto egress;
    }

    if (json_unpack(cfg, "{s?I,s:o}", "t", &t, "pins", &pins) != 0) {
        fprintf(stderr, "Config missing 'pins' attribute!\n");
        goto egress;
    }

    if (t < 1 || t > npins(pins)) {
        fprintf(stderr, "Invalid threshold (required: 1 <= %lld <= %lld)!\n",
                t, npins(pins));
        goto egress;
    }

    /* Generate the SSS polynomial. */
    sss = sss_generate(32, t);
    if (!sss) {
        fprintf(stderr, "Generating SSS!\n");
        goto egress;
    }

    if (json_object_set_new(sss, "pins", json_object()) < 0)
        goto egress;

    /* Encrypt each key share with a child pin. */
    json_object_foreach(pins, key, val) {
        char cmd[PATH_MAX] = {};
        json_t *arr = NULL;
        json_t *pin = NULL;
        size_t i = 0;

        if (!mkcmd(key, cmd, sizeof(cmd)))
            goto egress;

        if (json_is_object(val))
            val = json_pack("[O]", val);
        else if (json_is_array(val))
            val = json_incref(val);
        else
            goto egress;

        if (json_object_set_new(pins, key, val) != 0)
            goto egress;

        if (json_object_set_new(json_object_get(sss, "pins"),
                                key, arr = json_array()) < 0)
            goto egress;

        json_array_foreach(val, i, pin) {
            char *args[] = { cmd, "encrypt", NULL, NULL };
            uint8_t *pnt = NULL;
            FILE *pipe = NULL;
            size_t pntl = 0;
            pid_t pid = 0;

            args[2] = json_dumps(pin, JSON_SORT_KEYS | JSON_COMPACT);
            if (!args[2])
                goto egress;

            pnt = sss_point(sss, &pntl);
            if (!pnt) {
                memset(args[2], 0, strlen(args[2]));
                free(args[2]);
                goto egress;
            }

            pipe = call(args, pnt, pntl, &pid);
            memset(args[2], 0, strlen(args[2]));
            memset(pnt, 0, pntl);
            free(args[2]);
            free(pnt);
            if (!pipe)
                goto egress;

            jwe = json_loadf(pipe, 0, NULL);
            fclose(pipe);
            waitpid(pid, NULL, 0);
            if (!jwe)
                goto egress;

            if (json_array_append_new(arr, jwe) < 0) {
                jwe = NULL;
                goto egress;
            }

            jwe = NULL;
        }
    }

    /* Perform encryption using the key. */
    if (json_unpack(sss, "{s:[s]}", "e", &key) != 0)
        goto egress;

    cek = json_pack("{s:s,s:s}", "kty", "oct", "k", key);
    if (!cek)
        goto egress;

    if (json_object_del(sss, "e") != 0)
        goto egress;

    jwe = json_pack("{s:{s:s,s:s},s:{s:O}}",
                    "protected",
                        "alg", "dir",
                        "clevis.pin", "sss",
                    "unprotected",
                        "clevis.pin.sss", sss);
    if (!jwe)
        goto egress;

    if (!jose_jwe_encrypt(jwe, cek, pt, ptl))
        goto egress;

    json_dumpf(jwe, stdout, JSON_SORT_KEYS | JSON_COMPACT);
    ret = EXIT_SUCCESS;

egress:
    memset(pt, 0, ptl);
    json_decref(cfg);
    json_decref(cek);
    json_decref(sss);
    json_decref(jwe);
    free(pt);
    return ret;
}

struct pin {
    struct pin *prev;
    struct pin *next;
    uint8_t *pt;
    FILE *file;
    pid_t pid;
};

static size_t
nchldrn(const struct pin *pins, bool response)
{
    size_t n = 0;

    for (const struct pin *p = pins->next; p != pins; p = p->next) {
        if (response && p->pt)
            n++;
        else if (!response)
            n++;
    }

    return n;
}

static int
cmd_decrypt(int argc, char *argv[])
{
    struct pin chldrn = { &chldrn, &chldrn };
    const json_t *val = NULL;
    int ret = EXIT_FAILURE;
    const char *key = NULL;
    json_t *pins = NULL;
    json_t *jwe = NULL;
    json_t *p = NULL;
    json_int_t t = 1;
    int epoll = -1;
    size_t pl = 0;

    epoll = epoll_create1(EPOLL_CLOEXEC);
    if (epoll < 0)
        return ret;

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        goto egress;

    if (json_unpack(jwe, "{s:{s:{s:I,s:o,s:O}}}", "unprotected",
                    "clevis.pin.sss", "t", &t, "p", &p, "pins", &pins) != 0)
        goto egress;

    pl = jose_b64_dlen(json_string_length(p));
    if (pl == 0)
        goto egress;

    json_object_foreach(pins, key, val) {
        char cmd[PATH_MAX] = {};
        json_t *v = NULL;
        size_t i = 0;

        if (!mkcmd(key, cmd, sizeof(cmd)))
            goto egress;

        json_array_foreach(val, i, v) {
            char *args[] = { cmd, "decrypt", NULL };
            struct pin *pin = NULL;
            char *out = NULL;

            pin = calloc(1, sizeof(*pin));
            if (!pin)
                goto egress;

            chldrn.next->prev = pin;
            pin->next = chldrn.next;
            pin->prev = &chldrn;
            chldrn.next = pin;

            out = json_dumps(v, JSON_SORT_KEYS | JSON_COMPACT);
            if (!out)
                goto egress;

            pin->file = call(args, out, strlen(out), &pin->pid);
            memset(out, 0, strlen(out));
            free(out);
            if (!pin->file)
                goto egress;

            if (epoll_ctl(epoll, EPOLL_CTL_ADD, fileno(pin->file),
                          &(struct epoll_event) {
                              .events = EPOLLIN | EPOLLPRI,
                              .data.fd = fileno(pin->file)
                          }) < 0)
                goto egress;
        }
    }

    json_decref(pins);
    pins = json_array();
    if (!pins)
        goto egress;

    for (struct epoll_event e; true; ) {
        int r = 0;

        r = epoll_wait(epoll, &e, 1, -1);
        if (r != 1)
            break;

        for (struct pin *pin = chldrn.next; pin != &chldrn; pin = pin->next) {
            if (e.data.fd != fileno(pin->file))
                continue;

            if (e.events & (EPOLLIN | EPOLLPRI)) {
                size_t ptl = 0;
                pin->pt = readall(pin->file, &ptl);
                if (!pin->pt)
                    goto egress;
                if (ptl != pl * 2) {
                    memset(pin->pt, 0, ptl);
                    free(pin->pt);
                    pin->pt = NULL;
                    goto egress;
                }
            }

            fclose(pin->file);
            pin->file = NULL;

            waitpid(pin->pid, NULL, 0);
            pin->pid = 0;

            if (!pin->pt) {
                pin->next->prev = pin->prev;
                pin->prev->next = pin->next;
                free(pin);
            }

            break;
        }

        if (nchldrn(&chldrn, false) < (size_t) t ||
            nchldrn(&chldrn, true) >= (size_t) t)
            break;
    }

    if (nchldrn(&chldrn, true) >= (size_t) t) {
        jose_buf_auto_t *pt = NULL;
        const uint8_t *xy[t];
        json_t *cek = NULL;
        size_t i = 0;

        for (struct pin *pin = chldrn.next; pin != &chldrn; pin = pin->next) {
            if (pin->pt && i < (size_t) t)
                xy[i++] = pin->pt;
        }

        cek = json_pack("{s:s,s:o}", "kty", "oct", "k", sss_recover(p, t, xy));
        if (!cek)
            goto egress;

        pt = jose_jwe_decrypt(jwe, cek);
        json_decref(cek);
        if (!pt)
            goto egress;

        fwrite(pt->data, pt->size, 1, stdout);
        ret = EXIT_SUCCESS;
    }

egress:
    while (chldrn.next != &chldrn) {
        struct pin *pin = chldrn.next;

        if (pin->pt) {
            memset(pin->pt, 0, pl * 2);
            free(pin->pt);
        }

        if (pin->file)
            fclose(pin->file);

        if (pin->pid > 0) {
            kill(pin->pid, SIGTERM);
            waitpid(pin->pid, NULL, 0);
        }

        pin->next->prev = pin->prev;
        pin->prev->next = pin->next;
        free(pin);
    }

    json_decref(pins);
    json_decref(jwe);
    close(epoll);
    return ret;
}

int
main(int argc, char *argv[])
{
    if (argc == 3 && strcmp(argv[1], "encrypt") == 0)
        return cmd_encrypt(argc, argv);

    if (argc == 2 && strcmp(argv[1], "decrypt") == 0)
        return cmd_decrypt(argc, argv);

    fprintf(stderr, "Usage: %s encrypt CONFIG\n", argv[0]);
    fprintf(stderr, "   or: %s decrypt\n", argv[0]);
    return EXIT_FAILURE;
}