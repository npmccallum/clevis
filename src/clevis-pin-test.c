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

#include <jose/jwk.h>
#include <jose/jwe.h>

#include <sys/types.h>
#include <sys/wait.h>

#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

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

static int
encrypt(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    json_t *cfg = NULL;
    json_t *cek = NULL;
    json_t *jwe = NULL;
    uint8_t *pt = NULL;
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

    cek = json_pack("{s:s}", "alg", "A128CBC-HS256");
    if (!cek) {
        fprintf(stderr, "Error making CEK!\n");
        goto egress;
    }

    if (!jose_jwk_generate(cek)) {
        fprintf(stderr, "Error generating CEK!\n");
        goto egress;
    }

    jwe = json_pack("{s:{s:s},s:{s:O,s:O}}",
                    "protected", "alg", "dir",
                    "unprotected",
                        "fail", json_object_get(cfg, "fail"), "cek", cek);
    if (!jwe) {
        fprintf(stderr, "Error making JWE!\n");
        goto egress;
    }

    if (!jose_jwe_encrypt(jwe, cek, pt, ptl)) {
        fprintf(stderr, "Error encrypting!\n");
        goto egress;
    }

    json_dumpf(jwe, stdout, JSON_SORT_KEYS | JSON_COMPACT);
    fprintf(stdout, "\n");
    ret = EXIT_SUCCESS;

egress:
    memset(pt, 0, ptl);
    json_decref(cfg);
    json_decref(cek);
    json_decref(jwe);
    free(pt);
    return ret;
}

static int
decrypt(int argc, char *argv[])
{
    int ret = EXIT_FAILURE;
    json_t *cek = NULL;
    json_t *jwe = NULL;
    uint8_t *pt = NULL;
    size_t ptl = 0;
    int fail = 0;

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        goto egress;

    if (json_unpack(jwe, "{s:{s:b,s:o}}",
                    "unprotected", "fail", &fail, "cek", &cek) < 0 || fail)
        goto egress;

    pt = jose_jwe_decrypt(jwe, cek, &ptl);
    if (!pt)
        goto egress;

    if (fwrite(pt, ptl, 1, stdout) != 1)
        goto egress;

    ret = EXIT_SUCCESS;

egress:
    memset(pt, 0, ptl);
    json_decref(cek);
    json_decref(jwe);
    free(pt);
    return ret;
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
