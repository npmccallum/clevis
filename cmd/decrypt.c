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
#include <sys/un.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define _str(x) # x
#define str(x) _str(x)

#define EPE(evts, efd) (&(struct epoll_event) { (evts), { .fd = (efd) } })

enum jsonrpc_error {
    JSONRPC_ERROR_PARSE_ERROR = -32700,
    JSONRPC_ERROR_INVALID_REQUEST = -32600,
    JSONRPC_ERROR_METHOD_NOT_FOUND = -32601,
    JSONRPC_ERROR_INVALID_PARAMS = -32602,
    JSONRPC_ERROR_INTERNAL_ERROR = -32603,
};

static struct termios old = {};
static json_t *reg = NULL;
static int tty = -1;

static int
random_b64(char *str, size_t len)
{
    uint8_t buf[jose_b64_dlen(len)];
    int fd = 0;

    fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0)
        return -errno;

    for (ssize_t all = 0, now = 0; all < (ssize_t) sizeof(buf); all += now) {
        now = read(fd, &buf[all], sizeof(buf) - all);
        if (now < 0) {
            close(fd);
            return -errno;
        }
    }

    jose_b64_encode_buf(buf, sizeof(buf), str);
    close(fd);
    return 0;
}

static int
open_socket(void)
{
    struct sockaddr_un addr = {};
    int fd = 0;

    fd = random_b64(&addr.sun_path[1], sizeof(addr.sun_path) - 2);
    if (fd < 0)
        return fd;

    fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -errno;

    if (bind(fd, &addr, sizeof(addr)) < 0) {
        close(fd);
        return -errno;
    }

    if (listen(fd, 1024) < 0) {
        close(fd);
        return -errno;
    }

    setenv("CLEVIS_SOCKET", &addr.sun_path[1], 1);
    return fd;
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
on_connect(int epfd, int fd)
{
    struct ucred ucred = {};
    socklen_t len = sizeof(ucred);
    int sock;

    sock = accept(fd, NULL, NULL);
    if (sock < 0)
        return true;

    if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &ucred, &len) < 0) {
        close(sock);
        return true;
    }

    if (ucred.uid != getuid() ||
        ucred.gid != getgid() ||
        ucred.pid == 0        ||
        getpgid(ucred.pid) != getpid()) {
        fprintf(stderr, "Connection PID %d was rejected\n", ucred.pid);
        close(sock);
        return true;
    }

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock,
                  EPE(EPOLLIN | EPOLLPRI | EPOLLRDHUP, sock)) < 0)
        close(sock);

    return true;
}

static bool
on_password(int epfd, int fd)
{
    static json_t *pwd = NULL;
    const json_t *jfd = NULL;
    json_auto_t *tmp = NULL;
    const char *tok = NULL;
    char c = 0;

    if (read(fd, &c, 1) != 1)
        return false;

    if (c != '\n') {
        tmp = pwd;
        pwd = json_pack("s+%", pwd ? json_string_value(pwd) : "", &c, 1);
        return true;
    }

    json_object_foreach(json_object_get(reg, "lcl"), tok, jfd) {
        json_auto_t *req = NULL;

        req = json_pack("{s:s,s:s,s:s,s:{s:O}}", "jsonrpc", "2.0", "id", tok,
                        "method", "clevis.pwd.check", "params", "pwd", pwd);
        json_dumpfd(req, json_integer_value(jfd),
                    JSON_COMPACT | JSON_SORT_KEYS);
    }
}

static void
close_tty(int epfd)
{
    if (tty < 0)
        return;

    epoll_ctl(epfd, EPOLL_CTL_DEL, tty, NULL);
    tcsetattr(tty, TCSANOW, &old);
    close(tty);
    tty = -1;
}

static json_t *
clevis_pwd_query(int epfd, int fd, const json_t *id, const json_t *params)
{
    json_auto_t *reply = NULL;
    json_t *section = NULL;
    char token[33] = {};
    int local = false;

    if (json_unpack((json_t *) params, "{s?s}", "local", &local) < 0)
        return json_pack("{s:s,s:O,s:{s:i,s:s}}",
                         "jsonrpc", "2.0", "id", id,
                         "error",
                            "code", JSONRPC_ERROR_INVALID_PARAMS,
                            "message", "Invalid parameters");

    if (random_b64(token, sizeof(token) - 1) < 0)
        goto error;

    section = json_object_get(reg, local ? "lcl" : "rem");
    if (json_object_set_new(section, token, json_integer(fd)) < 0)
        goto error;

    reply = json_pack("{s:s,s:O,s:{s:s}}",
                      "jsonrpc", "2.0", "id", id,
                      "result", "id", token);
    if (!reply)
        goto error;

    if (tty < 0) {
        struct termios new = {};

        tty = open("/dev/tty", O_RDWR);
        if (tty < 0)
            goto error;

        if (tcgetattr(tty, &old) < 0) {
            close(tty);
            tty = -1;
            goto error;
        }

        new = old;
        new.c_lflag &= ~ECHO;
        new.c_lflag |= ICANON;
        new.c_lflag |= ECHONL;

        if (tcsetattr(tty, TCSANOW, &new) < 0) {
            close_tty(epfd);
            goto error;
        }

        if (epoll_ctl(epfd, EPOLL_CTL_ADD, tty,
                      EPE(EPOLLIN | EPOLLPRI | EPOLLRDHUP, tty)) < 0) {
            close_tty(epfd);
            goto error;
        }

        if (dprintf(tty, "Password: ") < 0) {
            close_tty(epfd);
            goto error;
        }
    }

    return json_incref(reply);

error:
    return json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0",
                     "id", id, "error", "code",
                     JSONRPC_ERROR_INTERNAL_ERROR,
                     "message", "Internal error");
}

static bool
unregister(const char *token, int fd)
{
    const char *name = NULL;
    bool unreg = false;
    json_t *sec = NULL;
    size_t cnt = 0;

    json_object_foreach(reg, name, sec) {
        const char *tok = NULL;
        json_t *jfd = NULL;

        json_object_foreach(sec, tok, jfd) {
            if (unreg)
                continue;

            if (token && strcmp(token, tok) != 0)
                continue;

            if (!json_is_integer(jfd))
                continue;

            if (json_integer_value(jfd) != fd)
                continue;

            unreg = json_object_del(sec, tok) == 0;
        }

        cnt += json_object_size(sec);
    }

    if (cnt == 0 && tty >= 0)
        close_tty();

    return unreg;
}

static json_t *
clevis_pwd_abort(int epfd, int fd, const json_t *id, const json_t *params)
{
    const char *token = NULL;

    if (json_unpack((json_t *) params, "{s:s}", "id", &token) < 0)
        return json_pack("{s:s,s:O,s:{s:i,s:s}}",
                         "jsonrpc", "2.0", "id", id,
                         "error",
                            "code", JSONRPC_ERROR_INVALID_PARAMS,
                            "message", "Invalid parameters");

    unregister(token, fd);

    return json_pack("{s:s,s:O,s:{}}", "jsonrpc", "2.0", "id", id, "result");
}

static struct {
    const char *cmd;
    json_t *(*fnc)(int epfd, int fd, const json_t *id, const json_t *params);
} methods[] = {
    { "clevis.pwd.query", clevis_pwd_query },
    { "clevis.pwd.abort", clevis_pwd_abort },
    {}
};

static bool
on_request(int epfd, int fd)
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
        unregister(NULL, fd);
        close(fd);
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

    for (size_t i = 0; methods[i].cmd; i++) {
        if (strcmp(cmd, methods[i].cmd) != 0)
            continue;

        rep = methods[i].fnc(epfd, fd, id, params);
        goto reply;
    }

    rep = json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0", "id", id,
                    "error", "code", JSONRPC_ERROR_METHOD_NOT_FOUND,
                    "message", "Method not found");

reply:
    if (!rep)
        rep = json_pack("{s:s,s:O,s:{s:i,s:s}}", "jsonrpc", "2.0", "id", id,
                        "error", "code", JSONRPC_ERROR_INTERNAL_ERROR,
                        "message", "Internal error");

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
    int sock = -1;
    int epfd = -1;

    reg = json_pack("{s:{},s:{}}", "remote", "local");

    signal(SIGCHLD, on_sigchld);

    if (getsid(0) != getpid() && setsid() < 0) {
        fprintf(stderr, "Unable to create session: %s\n", strerror(errno));
        goto error;
    }

    epfd = epoll_create1(EPOLL_CLOEXEC);
    if (epfd < 0) {
        fprintf(stderr, "Error creating epoll: %s\n", strerror(errno));
        goto error;
    }

    sock = open_socket();
    if (sock < 0) {
        fprintf(stderr, "Unable to open socket: %s", strerror(-sock));
        goto error;
    }

    if (epoll_ctl(epfd, EPOLL_CTL_ADD, sock,
                  EPE(EPOLLIN | EPOLLRDHUP | EPOLLPRI, sock)) < 0) {
        fprintf(stderr, "Error creating epoll watch: %s\n", strerror(errno));
        goto error;
    }

    if (!start_child(argc, argv))
        goto error;

    for (bool s = true; s && epoll_wait(epfd, &event, 1, -1) > 0; ) {
        if (event.data.fd == sock)
            s = on_connect(epfd, event.data.fd);
        else if (event.data.fd == tty)
            s = on_password(epfd, event.data.fd);
        else
            s = on_request(epfd, event.data.fd);
    }

error:
    if (sock >= 0) close(sock);
    if (epfd >= 0) close(epfd);
    json_decref(reg);
    return EXIT_FAILURE;
}
