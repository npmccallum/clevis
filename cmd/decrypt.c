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
#include <jose/jose.h>

#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <signal.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define _str(x) # x
#define str(x) _str(x)

#define EPE(evts, efd) (&(struct epoll_event) { (evts), { .fd = (efd) } })

static int pwd = -1;

static bool
open_socket(int sock[2])
{
    char sockstr[32] = {};

    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sock) < 0) {
        fprintf(stderr, "Error creating socket: %s\n", strerror(errno));
        return false;
    }

    if (fcntl(sock[1], F_SETFD, FD_CLOEXEC) < 0) {
        fprintf(stderr, "Error settings FD_CLOEXEC: %s\n", strerror(errno));
        close(sock[0]);
        close(sock[1]);
        return false;
    }

    snprintf(sockstr, sizeof(sockstr), "%d", sock[0]);
    setenv("CLEVIS_SOCKET", sockstr, 1);
    return true;
}

static bool
start_child(int argc, char *argv[])
{
    char path[PATH_MAX] = {};
    json_auto_t *jwe = NULL;
    json_auto_t *hdr = NULL;
    const char *cmd = NULL;
    const char *pin = NULL;
    int fds[] = { -1, -1 };
    FILE *file = NULL;
    pid_t pid = 0;
    int r = 0;

    cmd = secure_getenv("CLEVIS_CMD_DIR");
    if (!cmd)
        cmd = str(CLEVIS_CMD_DIR);

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe || argc != 1) {
        fprintf(stderr, "Usage: %s < JWE\n", argv[0]);
        return false;
    }

    hdr = jose_jwe_merge_header(jwe, NULL);
    if (!hdr) {
        fprintf(stderr, "Error merging JWE header!\n");
        return false;
    }

    if (json_unpack(hdr, "{s:s}", "clevis.pin", &pin) != 0) {
        fprintf(stderr, "JWE header missing clevis.pin!\n");
        return false;
    }

    for (size_t i = 0; pin[i]; i++) {
        if (!isalnum(pin[i]) && pin[i] != '-') {
            fprintf(stderr, "Invalid pin name: %s\n", pin);
            return false;
        }
    }

    if (!pin[0]) {
        fprintf(stderr, "Empty pin name\n");
        return false;
    }

    r = snprintf(path, sizeof(path), "%s/pins/%s", cmd, pin);
    if (r < 0 || r == sizeof(path)) {
        fprintf(stderr, "Invalid pin name: %s\n", pin);
        return false;
    }

    if (pipe(fds) < 0)
        return false;

    pid = fork();
    if (pid != 0) {
        dup2(fds[0], STDIN_FILENO);
        close(fds[0]);
        close(fds[1]);
        execl(path, path, "decrypt", NULL);
        exit(EXIT_FAILURE);
    }

    file = fdopen(fds[1], "a");
    close(fds[0]);
    if (!file) {
        close(fds[1]);
        return false;
    }

    json_dumpf(jwe, file, JSON_SORT_KEYS | JSON_COMPACT);
    fclose(file);
    return true;
}

static bool
receive_fd(int epfd, int fd)
{
    struct msghdr msg = {
        .msg_control = &(char[256]) {},
        .msg_controllen = 256,
        .msg_iov = &(struct iovec) {
            .iov_base = &(char[256]) {},
            .iov_len = 256,
        },
        .msg_iovlen = 1,
    };

    if (recvmsg(fd, &msg, 0) < 0) {
        fprintf(stderr, "Error receiving message: %s\n", strerror(errno));
        return false;
    }

    fd = 0;
    memcpy(&fd, CMSG_DATA(CMSG_FIRSTHDR(&msg)), sizeof(fd));

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, fd, EPE(EPOLLIN | EPOLLPRI, fd)) < 0) {
        fprintf(stderr, "Error creating epoll watch: %s\n", strerror(errno));
        close(fd);
        return false;
    }

    return true;
}

static bool
receive_pwd(int epfd, int fd)
{
}

enum jsonrpc_error {
    JSONRPC_ERROR_PARSE_ERROR = -32700,
    JSONRPC_ERROR_INVALID_REQUEST = -32600,
    JSONRPC_ERROR_METHOD_NOT_FOUND = -32601,
    JSONRPC_ERROR_INVALID_PARAMS = -32602,
    JSONRPC_ERROR_INTERNAL_ERROR = -32603,
};

static json_t *
handle_password_register(const json_t *id, const json_t *params)
{
    int local = false;

    if (json_unpack((json_t *) params, "{s?s}", "local", &local) < 0)
        return json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0", "id", id,
                         "error", "code", JSONRPC_ERROR_INVALID_PARAMS,
                         "message", "Invalid parameters");

    /* Register passsword handler */
#error TODO

    return json_pack("{s:s,s:O,s:{}}", "jsonrpc", "2.0", "id", id, "result");
}

static bool
handle_request(int epfd, int fd)
{
    const json_t *params = NULL;
    const json_t *id = NULL;
    json_auto_t *req = NULL;
    json_auto_t *rep = NULL;
    const char *ver = NULL;
    const char *cmd = NULL;
    char pkt[65507] = {};
    char *msg = NULL;
    ssize_t size = 0;

    size = recv(fd, pkt, sizeof(pkt), 0);
    if (size < 0) { /* Remove the closed fd */
        epoll_ctl(epfd, EPOLL_CTL_DEL, fd, NULL);
        close(fd);
#error remove pwd registration
        return true;
    }

    req = json_loadb(pkt, size, 0, NULL);
    if (!req) {
        rep = json_pack("{s:s,s:n,s:{s:i,s:s}}", "jsonrpc", "2.0", "id",
                        "error", "code", JSONRPC_ERROR_PARSE_ERROR,
                        "message", "Error parsing JSON");
        goto reply;
    }

    if (json_unpack(req, "{s:s,s:s,s:o,s:o}", "jsonrpc", &ver, "method", &cmd,
                    "params", &params, "id", &id) < 0
        || strcmp(ver, "2.0") != 0) {
        rep = json_pack("{s:s,s:n,s:{s:i,s:s}}", "jsonrpc", "2.0", "id",
                        "error", "code", JSONRPC_ERROR_INVALID_REQUEST,
                        "message", "Invalid Request object");
        goto reply;
    }

    if (strcmp(cmd, "clevis.pwd.reg") != 0) {
        rep = json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0", "id", id,
                        "error", "code", JSONRPC_ERROR_METHOD_NOT_FOUND,
                        "message", "Method not found");
        goto reply;
    }

    rep = handle_password_register(id, params);
    if (!rep)
        rep = json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0", "id", id,
                        "error", "code", JSONRPC_ERROR_INTERNAL_ERROR,
                        "message", "Internal error");

reply:
    msg = json_dumps(rep, JSON_COMPACT | JSON_SORT_KEYS);
    if (!msg) /* OOM */
        return false;
    if (strlen(msg) > sizeof(pkt)) { /* Message too big */
        free(msg);
        return false;
    }

    send(fd, msg, strlen(msg), 0);
    free(msg);
    return true;
}

static void
on_sigchld(int sig)
{
    int status = 0;
    pid_t pid = -1;

    pid = wait(&status);
    if (pid >= 0)
        _exit(WEXITSTATUS(status));
}

int
main(int argc, char *argv[])
{
    struct epoll_event event = {};
    int sock[2] = { -1, -1 };
    int epfd = -1;

    signal(SIGCHLD, on_sigchld);

    if (!open_socket(sock))
        return EXIT_FAILURE;

    if (!start_child(argc, argv)) {
        close(sock[0]);
        close(sock[1]);
        return EXIT_FAILURE;
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    close(sock[0]);
    if (epfd < 0) {
        fprintf(stderr, "Error creating epoll: %s\n", strerror(errno));
        close(sock[1]);
        return EXIT_FAILURE;
    }

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock[1],
                  EPE(EPOLLIN | EPOLLPRI, sock[1])) < 0) {
        fprintf(stderr, "Error creating epoll watch: %s\n", strerror(errno));
        close(sock[1]);
        close(epfd);
        return EXIT_FAILURE;
    }

    while (epoll_wait(epfd, &event, 1, -1) > 0) {
        bool success = false;

        if (event.data.fd == sock[1])
            success = receive_fd(epfd, event.data.fd);
        else if (event.data.fd == pwd)
            success = receive_pwd(epfd, event.data.fd);
        else
            success = handle_request(epfd, event.data.fd);

        if (!success)
            goto error;
    }

    close(sock[1]);
    close(epfd);
    return EXIT_SUCCESS;

error:
    close(sock[1]);
    close(epfd);
    return EXIT_FAILURE;
}
