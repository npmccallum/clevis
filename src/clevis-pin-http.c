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

#include "http.h"

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

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
    const char *url = NULL;
    uint8_t ky[32] = {};
    json_t *cfg = NULL;
    json_t *cek = NULL;
    json_t *jwe = NULL;
    uint8_t *pt = NULL;
    size_t ptl = 0;
    int r = 0;

    const struct body send = { sizeof(ky), "application/octet-string", ky };

    pt = readall(stdin, &ptl);
    if (!pt)
        return EXIT_FAILURE;

    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg)
        goto egress;

    if (json_unpack(cfg, "{s:s}", "url", &url) != 0)
        goto egress;

    cek = json_pack("{s:s,s:i}", "kty", "oct", "bytes", sizeof(ky));
    if (!cek)
        goto egress;

    if (!jose_jwk_generate(cek))
        goto egress;

    jwe = json_pack("{s:{s:s},s:{s:s}}",
                    "protected", "alg", "dir",
                    "unprotected", "url", url);
    if (!jwe)
        goto egress;

    if (!jose_jwe_encrypt(jwe, cek, pt, ptl))
        goto egress;

    if (!jose_b64_decode_json_buf(json_object_get(cek, "k"), ky))
        goto egress;

    r = http(url, HTTP_PUT, NULL, &send, NULL);
    if (r != 200)
        goto egress;

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
    const char *url = NULL;
    json_t *cek = NULL;
    json_t *jwe = NULL;
    uint8_t *pt = NULL;
    size_t ptl = 0;
    int r = 0;

    struct header headers[] = {{"Accept", "application/octet-string"}, {}};
    struct body recv = {};

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        goto egress;

    if (json_unpack(jwe, "{s:{s:s}}", "unprotected", "url", &url) != 0)
        goto egress;

    r = http(url, HTTP_GET, headers, NULL, &recv);
    if (r != 200)
        goto egress;

    if (!recv.body || recv.size != 32)
        goto egress;

    if (strcasecmp(recv.type, "application/octet-string") != 0)
        goto egress;

    cek = json_pack("{s:s,s:i}", "kty", "oct", "bytes",
                    jose_b64_encode_json(recv.body, recv.size));
    if (!cek)
        goto egress;

    pt = jose_jwe_decrypt(jwe, cek, &ptl);
    if (!pt)
        goto egress;

    fwrite(pt, ptl, 1, stdout);
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
