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

#include <jansson.h>
#include <string.h>

static int
provision(int argc, char *argv[])
{
    const char *pin = NULL;
    json_t *cfg = NULL;
    json_t *lay = NULL;

    if (argc != 3)
        goto usage;

    lay = json_loads(argv[2], 0, NULL);
    if (!lay) {
        fprintf(stderr, "Error parsing layout!\n");
        goto usage;
    }

    if (json_unpack(lay, "{s:s,s:o}", "pin", &pin, "cfg", &cfg) != 0) {
        fprintf(stderr, "Layout is missing required attributes!\n");
        goto usage;
    }


usage:
    fprintf(stderr, "Usage: %s provision LAYOUT\n", argv[0]);
    return EXIT_FAILURE;
}

static int
acquire(int argc, char *argv[])
{
/*
    optind = 2;

    for (int c; (c = getopt(argc, argv, "I:f:h")) != -1; ) {
    }

usage:*/
    fprintf(stderr, "Usage: %s acquire [-h] [-f format] -i input\n", argv[0]);
    return EXIT_FAILURE;
}

int
main(int argc, char *argv[])
{
    if (argc > 1) {
        if (strcmp("provision", argv[1]) == 0)
            return provision(argc, argv);

        if (strcmp("acquire", argv[1]) == 0)
            return acquire(argc, argv);
    }

    fprintf(stderr, "Usage: %s [provision|acquire] ...\n", argv[0]);
    return EXIT_FAILURE;
}
