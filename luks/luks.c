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

#include "luks.h"

#include <luksmeta.h>
#include <zlib.h>

#include <string.h>
#include <errno.h>

static const luksmeta_uuid_t CLEVIS_LUKS_UUID = {
    0x08, 0x02, 0x32, 0x6e, 0xc7, 0x97, 0x2c, 0x59,
    0x00, 0x61, 0x1b, 0xde, 0x16, 0x27, 0xbd, 0x83
};

static uint8_t *
comp_deflate(const uint8_t *buf, size_t len, size_t *out)
{
    uint8_t *o = NULL;
    z_stream strm = {};

    strm.next_in = (uint8_t *) buf;
    strm.avail_in = len;

    if (deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED, -MAX_WBITS,
                     MAX_MEM_LEVEL, Z_DEFAULT_STRATEGY) != Z_OK)
        return NULL;

    while (strm.avail_in > 0) {
        uint8_t *tmp = NULL;

        strm.avail_out = 16 * 1024; /* 16K blocks */

        tmp = realloc(o, strm.total_out + strm.avail_out);
        if (!tmp)
            goto error;

        o = tmp;
        strm.next_out = &o[strm.total_out];

        if (deflate(&strm, Z_FINISH) != Z_STREAM_END)
            goto error;
    }

    *out = strm.total_out;
    deflateEnd(&strm);
    return o;

error:
    deflateEnd(&strm);
    if (o)
        memset(o, 0, *out);
    free(o);
    return NULL;
}

static uint8_t *
comp_inflate(const uint8_t *buf, size_t len, size_t *out)
{
    uint8_t *o = NULL;
    z_stream strm = {};

    strm.next_in = (uint8_t *) buf;
    strm.avail_in = len;

    if (inflateInit2(&strm, -MAX_WBITS) != Z_OK)
        return NULL;

    while (strm.avail_in > 0) {
        uint8_t *tmp = NULL;

        strm.avail_out = 16 * 1024; /* 16K blocks */

        tmp = realloc(o, strm.total_out + strm.avail_out);
        if (!tmp)
            goto error;

        o = tmp;
        strm.next_out = &o[strm.total_out];

        if (inflate(&strm, Z_FINISH) != Z_STREAM_END)
            goto error;
    }

    *out = strm.total_out;
    inflateEnd(&strm);
    return o;

error:
    inflateEnd(&strm);
    if (o)
        memset(o, 0, *out);
    free(o);
    return NULL;
}

bool
luks_store(struct crypt_device *cd, int slot, const json_t *json)
{
    static const char *msg =
        "The specified block device is not initialized for metadata storage.\n"
        "Attempting to initialize it may result in data loss if data was\n"
        "already written into the LUKS header gap in a different format.\n"
        "A backup is advised before initialization is performed.\n\n";

    uint8_t *buf = NULL;
    char *enc = NULL;
    size_t bufl = 0;
    int r = 0;

    enc = json_dumps(json, JSON_SORT_KEYS | JSON_COMPACT);
    if (!enc)
        return false;

    buf = comp_deflate((uint8_t *) enc, strlen(enc), &bufl);
    free(enc);
    if (!buf)
        return false;

    r = luksmeta_set(cd, slot, CLEVIS_LUKS_UUID, buf, bufl);
    if (r == -ENOENT) {
        char c = 'X';

        fprintf(stderr, "%s", msg);

        while (!strchr("YyNn", c)) {
            fprintf(stderr, "Do you wish to initialize %s? [yn] ",
                    crypt_get_device_name(cd));
            c = getc(stdin);
        }

        if (strchr("Nn", c)) {
            free(buf);
            return false;
        }

        r = luksmeta_init(cd);
        if (r >= 0)
            r = luksmeta_set(cd, slot, CLEVIS_LUKS_UUID, buf, bufl);
    }

    if (r < 0)
        fprintf(stderr, "Error during metadata write: %s\n", strerror(-r));

    free(buf);
    return r >= 0;
}

json_t *
luks_load(struct crypt_device *cd, int slot)
{
    uint8_t buf[64 * 1024] = {};
    luksmeta_uuid_t uuid = {};
    json_t *json = NULL;
    char *out = NULL;
    size_t bufl = 0;
    size_t outl = 0;
    int r = 0;

    r = luksmeta_get(cd, slot, uuid, buf, bufl);
    if (r != 0)
        return NULL;

    if (memcmp(uuid, CLEVIS_LUKS_UUID, sizeof(uuid)) != 0)
        return NULL;

    out = (char *) comp_inflate(buf, bufl, &outl);
    if (!out)
        return NULL;

    json = json_loadb(out, outl, 0, NULL);
    free(out);
    return json;
}
