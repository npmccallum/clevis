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

#include "pcmd.h"
#include "luks.h"

#include <libcryptsetup.h>
#include <luksmeta.h>
#include <jose/b64.h>

#include <string.h>
#include <sysexits.h>

#include <errno.h>

static struct crypt_device *
open_device(const char *device)
{
    struct crypt_device *cd = NULL;
    const char *type = NULL;
    int nerr = 0;

    nerr = crypt_init(&cd, device);
    if (nerr != 0) {
        fprintf(stderr, "Unable to open device (%s): %s\n",
                device, strerror(-nerr));
        return NULL;
    }

    nerr = crypt_load(cd, NULL, NULL);
    if (nerr != 0) {
        fprintf(stderr, "Unable to load device (%s): %s\n",
                device, strerror(-nerr));
        goto error;
    }

    type = crypt_get_type(cd);
    if (type == NULL) {
        fprintf(stderr, "Unable to determine device type for %s\n", device);
        goto error;
    }

    if (strcmp(type, CRYPT_LUKS1) != 0) {
        fprintf(stderr, "%s (%s) is not a LUKS device\n", device, type);
        goto error;
    }

    return cd;

error:
    crypt_free(cd);
    return NULL;
}

static bool
read_random(uint8_t buf[], size_t size)
{
    FILE *file = NULL;

    file = fopen("/dev/urandom", "r");
    if (!file)
        return false;

    size = fread(buf, size, 1, file);
    fclose(file);
    return size == 1;
}

int
main(int argc, char *argv[])
{
    struct crypt_device *cd = NULL;
    uint8_t *out = NULL;
    int ret = EX_IOERR;
    json_t *mtd = NULL;
    json_t *jwe = NULL;
    size_t outl = 0;
    int keysize = 0;
    int slot = -1;

    if (argc != 4) {
        fprintf(stderr, "Usage: %s DEVICE PIN CONFIG\n", argv[0]);
        return EX_USAGE;
    }

    cd = open_device(argv[1]);
    if (!cd)
        return EX_IOERR;

    keysize = crypt_get_volume_key_size(cd);
    if (keysize < 16) { /* Less than 128-bits. */
        fprintf(stderr, "Key size (%d) is too small!\n", keysize);
        crypt_free(cd);
        return EX_CONFIG;
    }

    uint8_t key[keysize];
    char b64[jose_b64_elen(keysize) + 1];

    if (!read_random(key, keysize)) {
        fprintf(stderr, "Unable to generate random key!\n");
        goto egress;
    }

    jose_b64_encode_buf(key, sizeof(key), b64);
    slot = crypt_keyslot_add_by_passphrase(cd, CRYPT_ANY_SLOT, NULL,
                                           0, b64, strlen(b64));
    memset(b64, 0, strlen(b64));
    if (slot < 0) {
        fprintf(stderr, "Error adding new slot!\n");
        goto egress;
    }

    out = pcmd(argv[0], argv[2], "encrypt", argv[3], key, sizeof(key), &outl);
    if (!out) {
        fprintf(stderr, "Error executing pin!\n");
        goto egress;
    }

    jwe = json_loadb((char *) out, outl, 0, NULL);
    free(out);
    if (!jwe) {
        fprintf(stderr, "Invalid pin output!\n");
        goto egress;
    }

    mtd = json_pack("{s:o,s:s}", "jwe", jwe, "pin", argv[2]);
    if (!mtd)
        goto egress;

    if (!luks_store(cd, slot, mtd)) {
        fprintf(stderr, "Error while writing metadata!\n");
        goto egress;
    }

    slot = -1;
    ret = 0;

egress:
    if (slot >= 0)
        crypt_keyslot_destroy(cd, slot);

    json_decref(mtd);
    crypt_free(cd);
    return ret;
}
