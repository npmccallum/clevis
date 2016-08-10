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

#include <jose/jwe.h>

#include <limits.h>
#include <libgen.h>
#include <unistd.h>
#include <stdio.h>
#include <sysexits.h>

int
main(int argc, char *argv[])
{
    char self[PATH_MAX] = {};
    char path[PATH_MAX] = {};
    const char *pin = NULL;
    json_t *jwe = NULL;
    json_t *hd = NULL;

    if (argc != 1) {
        fprintf(stderr, "Usage: %s < JWE\n", argv[0]);
        return EX_USAGE;
    }

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        return EX_DATAERR;

    hd = jose_jwe_merge_header(jwe, NULL);
    if (!hd)
        return EX_DATAERR;

    if (json_unpack(hd, "{s:s}", "clevis.pin", &pin) != 0)
        return EX_DATAERR;

    if (readlink("/proc/self/exe", self, sizeof(self)) < 0)
        return EX_IOERR;

    if (snprintf(path, sizeof(path), "%s/clevis-pin-%s",
                 dirname(self), pin) < 0)
        return EX_OSERR;

    execv(path, (char *[]) { path, "encrypt", argv[2] });
    fprintf(stderr, "No such pin: %s\n", argv[1]);
    return EX_DATAERR;
}
