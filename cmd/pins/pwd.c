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

#include "libreadall.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include <termios.h>
#include <unistd.h>
#include <string.h>

enum jsonrpc_error {
    JSONRPC_ERROR_PARSE_ERROR = -32700,
    JSONRPC_ERROR_INVALID_REQUEST = -32600,
    JSONRPC_ERROR_METHOD_NOT_FOUND = -32601,
    JSONRPC_ERROR_INVALID_PARAMS = -32602,
    JSONRPC_ERROR_INTERNAL_ERROR = -32603,
};

static json_t *
read_line(FILE *file)
{
    json_auto_t *line = NULL;

    for (char c = 0; c != '\n';) {
        json_auto_t *tmp = NULL;

        if (fread(&c, 1, 1, file) != 1)
            return NULL;

        tmp = line;
        line = json_pack("s+%", line ? json_string_value(line) : "", &c, 1);
        if (!line)
            return NULL;
    }

    return json_pack("s%", json_string_value(line),
                     json_string_length(line) - 1);
}

static json_t *
confirm_pwd(void)
{
    struct termios old = {};
    struct termios new = {};
    json_auto_t *pwd = NULL;
    json_t *ret = NULL;
    bool match = false;
    FILE *file = NULL;

    file = fopen("/dev/tty", "r+");
    if (!file)
        return NULL;

    if (tcgetattr(fileno(file), &old) < 0) {
        fclose(file);
        return NULL;
    }

    new = old;
    new.c_lflag &= ~ECHO;
    new.c_lflag |= ICANON;
    new.c_lflag |= ECHONL;

    if (tcsetattr(fileno(file), TCSANOW, &new) < 0)
        goto egress;

    while (!match) {
        json_auto_t *cpy = NULL;

        fprintf(file, "Password: ");

        json_decref(pwd);
        pwd = read_line(file);
        if (!pwd)
            goto egress;

        fprintf(file, "Confirm password: ");

        cpy = read_line(file);
        if (!cpy)
            goto egress;

        match = json_equal(pwd, cpy);
    }

    ret = json_incref(pwd);

egress:
    tcsetattr(fileno(file), TCSANOW, &old);
    fclose(file);
    return ret;
}

static int
encrypt(int argc, char *argv[])
{
    jose_buf_auto_t *pt = NULL;
    json_auto_t *cfg = NULL;
    json_auto_t *cek = NULL;
    json_auto_t *jwe = NULL;
    json_auto_t *pwd = NULL;

    pt = readall(stdin);
    if (!pt) {
        fprintf(stderr, "Error reading input!\n");
        return EXIT_FAILURE;
    }

    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Error parsing config!\n");
        return EXIT_FAILURE;
    }

    pwd = confirm_pwd();
    if (!pwd) {
        fprintf(stderr, "Error getting password!\n");
        return EXIT_FAILURE;
    }

    cek = json_object ();
    jwe = json_pack("{s:{s:s},s:{s:s}}",
                    "protected", "alg", "PBES2-HS256+A128KW",
                    "unprotected", "clevis.pin", "pwd");
    if (!cek || !jwe)
        return EXIT_FAILURE;

    if (!jose_jwe_wrap(jwe, cek, pwd, NULL))
        return EXIT_FAILURE;

    if (!jose_jwe_encrypt(jwe, cek, pt->data, pt->size))
        return EXIT_FAILURE;

    json_dumpf(jwe, stdout, JSON_SORT_KEYS | JSON_COMPACT);
    fprintf(stdout, "\n");
    return EXIT_SUCCESS;
}

static void
cleanup_FILE(FILE **file)
{
    if (file && *file)
        fclose(*file);
    *file = NULL;
}

static FILE *
pwd_query(void)
{
    struct sockaddr_un addr = {};
    json_auto_t *req = NULL;
    json_auto_t *rep = NULL;
    const char *name = NULL;
    FILE *file = NULL;
    int fd = -1;

    name = getenv("CLEVIS_SOCKET");
    if (!name || strlen(name) > sizeof(addr.sun_path) - 2)
        return NULL;
    strcpy(&addr.sun_path[1], name);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0)
        return NULL;

    file = fdopen(fd, "r+");
    if (!file) {
        close(fd);
        return NULL;
    }

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0)
        goto error;

    req = json_pack("{s:s,s:i,s:s,s:{}}",
                    "jsonrpc", "2.0", "id", 0,
                    "method", "clevis.pwd.query",
                    "params", "local", 1);
    if (!req)
        goto error;

    if (json_dumpf(req, file, JSON_COMPACT | JSON_SORT_KEYS) < 0)
        goto error;

    rep = json_loadf(file, JSON_DISABLE_EOF_CHECK, NULL);
    if (!rep)
        goto error;

    if (json_unpack_ex(rep, NULL, JSON_VALIDATE_ONLY, "{s:s,s:i,s:{}}",
                       "jsonrpc", "2.0", "id", 0, "result") < 0)
        goto error;

    return file;

error:
    fclose(file);
    return NULL;
}

static int
decrypt(int argc, char *argv[])
{
    FILE __attribute__((cleanup(cleanup_FILE))) *sock = NULL;
    jose_buf_auto_t *pt = NULL;
    json_auto_t *jwe = NULL;
    json_auto_t *cek = NULL;

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        return EXIT_FAILURE;

    sock = pwd_query();
    if (!sock)
        return EXIT_FAILURE;

    while (!cek) {
        const json_t *params = NULL;
        const json_t *id = NULL;
        json_auto_t *req = NULL;
        json_auto_t *rep = NULL;
        const char *ver = NULL;
        const char *cmd = NULL;
        json_t *pwd = NULL;

        req = json_loadf(sock, JSON_DISABLE_EOF_CHECK, NULL);
        if (!req) {
            rep = json_pack("{s:s,s:n,s:{s:i,s:s}}", "jsonrpc", "2.0", "id",
                            "error", "code", JSONRPC_ERROR_PARSE_ERROR,
                            "message", "Error parsing JSON");
            json_dumpf(req, sock, JSON_COMPACT | JSON_SORT_KEYS);
            return EXIT_FAILURE;
        }

        if (json_unpack(req, "{s:s,s:s,s:o,s:o}",
                        "jsonrpc", &ver, "method", &cmd,
                        "params", &params, "id", &id) < 0
            || strcmp(ver, "2.0") != 0) {
            rep = json_pack("{s:s,s:{s:i,s:s}}",
                            "jsonrpc", "2.0",
                            "error",
                                "code", JSONRPC_ERROR_INVALID_REQUEST,
                                "message", "Invalid Request object");
            json_dumpf(req, sock, JSON_COMPACT | JSON_SORT_KEYS);
            return EXIT_FAILURE;
        }

        if (strcmp(cmd, "clevis.pwd.check") != 0) {
            rep = json_pack("{s:s,s:O,s:{s:i,s:s}}",
                            "jsonrpc", "2.0",
                            "id", id,
                            "error",
                                "code", JSONRPC_ERROR_METHOD_NOT_FOUND,
                                "message", "Method not found");
            goto reply;
        }

        if (json_unpack((json_t *) params, "{s:o}", "pwd", &pwd) < 0 ||
            !json_is_string(pwd)) {
            rep = json_pack("{s:s,s:O,s:{s:i,s:s}}",
                            "jsonrpc", "2.0",
                            "id", id,
                            "error",
                                "code", JSONRPC_ERROR_INVALID_PARAMS,
                                "message", "Invalid parameters");
            goto reply;
        }

        cek = jose_jwe_unwrap(jwe, pwd, NULL);
        rep = json_pack("{s:s,s:O,s:{s:b}}", "jsonrpc", "2.0",
                        "id", id, "result", "valid", cek != NULL);

reply:
        if (!rep)
            rep = json_pack("{s:s,s:O,s:{s:i,s:s}}",
                            "jsonrpc", "2.0",
                            "id", id,
                            "error",
                                "code", JSONRPC_ERROR_INVALID_PARAMS,
                                "message", "Invalid parameters");
        if (!rep)
            return EXIT_FAILURE;

        json_dumpf(rep, sock, JSON_COMPACT | JSON_SORT_KEYS);
    }

    pt = jose_jwe_decrypt(jwe, cek);
    if (!pt)
        return EXIT_FAILURE;

    if (fwrite(pt->data, pt->size, 1, stdout) != 1)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
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
