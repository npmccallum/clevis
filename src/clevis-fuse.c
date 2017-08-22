/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2017 Red Hat, Inc.
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

#define FUSE_USE_VERSION 26
#include <fuse.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>

#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <string.h>
#include <dirent.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <sys/poll.h>

#include <getopt.h>
#include <jansson.h>

#if O_LARGEFILE == 0
#undef O_LARGEFILE
#define O_LARGEFILE 100000
#endif

struct config {
    const char *src;
    pid_t *pids;
    char *pin;
    char *cfg;
};

static bool
mkrp(char rp[PATH_MAX], const char *path)
{
    struct fuse_context *ctx = fuse_get_context();
    struct config *cfg = ctx->private_data;

    if (strlen(cfg->src) + strlen(path) + 1 > PATH_MAX)
        return false;

    strcpy(rp, cfg->src);
    strcat(rp, path);
    return true;
}

static int
cf_getattr(const char *path, struct stat *st)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (lstat(rp, st) < 0)
        return -errno;

    return 0;
}

static int
cf_readlink(const char *path, char *link, size_t size)
{
    char rp[PATH_MAX];
    int r;

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    r = readlink(rp, link, size - 1);
    if (r < 0)
        return -errno;

    link[r] = 0;
    return 0;
}

static int
cf_mknod(const char *path, mode_t mode, dev_t dev)
{
    const struct fuse_context *ctx = fuse_get_context();
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (!S_ISREG(mode))
        return -EINVAL;

    if (mknod(rp, mode, dev) < 0)
        return -errno;

    if (chown(rp, ctx->uid, ctx->gid) < 0)
        return -errno;

    return 0;
}

static int
cf_mkdir(const char *path, mode_t mode)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (mkdir(rp, mode) < 0)
        return -errno;

    return 0;
}

static int
cf_unlink(const char *path)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (unlink(rp) < 0)
        return -errno;

    return 0;
}

static int
cf_rmdir(const char *path)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (rmdir(rp) < 0)
        return -errno;

    return 0;
}

static int
cf_symlink(const char *path, const char *link)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, link))
        return -ENAMETOOLONG;

    if (symlink(path, rp) < 0)
        return -errno;

    return 0;
}

static int
cf_rename(const char *path, const char *npath)
{
    char rp[PATH_MAX];
    char np[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (!mkrp(np, npath))
        return -ENAMETOOLONG;

    if (rename(rp, np) < 0)
        return -errno;

    return 0;
}

static int
cf_link(const char *path, const char *npath)
{
    char nrp[PATH_MAX];
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (!mkrp(nrp, npath))
        return -ENAMETOOLONG;

    if (link(rp, nrp) < 0)
        return -errno;

    return 0;
}

static int
cf_chmod(const char *path, mode_t mode)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (chmod(rp, mode) < 0)
        return -errno;

    return 0;
}

static int
cf_chown(const char *path, uid_t uid, gid_t gid)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (chown(rp, uid, gid) < 0)
        return -errno;

    return 0;
}

static int
cf_truncate(const char *path, off_t size)
{
    char rp[PATH_MAX];

    if (size != 0)
        return -EINVAL;

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (truncate(rp, size) < 0)
        return -errno;

    return 0;
}

static int
cf_utime(const char *path, struct utimbuf *ubuf)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (utime(rp, ubuf) < 0)
        return -errno;

    return 0;
}

static int
do_open(const char *path, mode_t mode, const uid_t *uid, const gid_t *gid,
        struct fuse_file_info *fi)
{
    struct fuse_context *ctx = fuse_get_context();
    struct config *cfg = ctx->private_data;
    struct pollfd pfd = {};
    int p[] = { -1, -1 };
    char rp[PATH_MAX];
    pid_t pid = 0;
    int f = -1;
    pid_t x;
    int r;

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    switch (fi->flags & O_ACCMODE) {
    case O_RDONLY: break;
    case O_WRONLY: if (!cfg->pin || !cfg->cfg) return -EROFS; break;
    default: return -EINVAL;
    }

    f = open(rp, fi->flags | O_CLOEXEC, mode);
    if (f < 0)
        goto error;

    if (uid && gid) {
        if (chown(rp, *uid, *gid) < 0)
            goto error;
    }

    if (pipe2(p, O_CLOEXEC) < 0)
        goto error;

    pid = fork();
    if (pid == -1)
        goto error;

    if (pid == 0) {
        const char *const env[] = { "PATH=" BINDIR, NULL };

        if (ioctl(STDIN_FILENO, TIOCNOTTY) < 0)
            exit(EXIT_FAILURE);

        switch (fi->flags & O_ACCMODE) {
        case O_RDONLY:
            if (dup2(f, STDIN_FILENO) < 0)
                break;

            if (dup2(p[1], STDOUT_FILENO) < 0)
                break;

            execle(BINDIR "/clevis", "clevis", "decrypt", NULL, env);
            break;

        case O_WRONLY:
            if (dup2(p[0], STDIN_FILENO) < 0)
                break;

            if (dup2(f, STDOUT_FILENO) < 0)
                break;

            execle(BINDIR "/clevis", "clevis", "encrypt",
                   cfg->pin, cfg->cfg, NULL, env);
            break;
        }

        exit(EXIT_FAILURE);
    }

    close(f);
    f = -1;

    switch (fi->flags & O_ACCMODE) {
    case O_RDONLY:
        pfd.fd = fi->fh = p[0];
        pfd.events = POLLIN;
        close(p[1]);
        p[1] = -1;
        break;

    case O_WRONLY:
        pfd.fd = fi->fh = p[1];
        pfd.events = POLLOUT;
        close(p[0]);
        p[0] = -1;
        break;
    }

    if (poll(&pfd, 1, -1) < 0)
        goto error;

    x = waitpid(pid, NULL, WNOHANG);
    if (x == -1 || x == pid) {
        errno = ENOKEY;
        goto error;
    }

    cfg->pids[pfd.fd] = pid;
    return 0;

error:
    r = errno;
    if (p[0] >= 0) close(p[0]);
    if (p[1] >= 0) close(p[1]);
    if (f >= 0) close(f);
    if (pid > 0) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }
    return -r;
}

static int
cf_open(const char *path, struct fuse_file_info *fi)
{
    int mask = O_LARGEFILE | O_ACCMODE;

    if (fi->flags & ~mask)
        return -EINVAL;

    return do_open(path, 0, NULL, NULL, fi);
}

static int
cf_read(const char *path, char *buf, size_t size, off_t offset,
        struct fuse_file_info *fi)
{
    struct fuse_context *ctx = fuse_get_context();
    struct config *cfg = ctx->private_data;
    ssize_t r = 0;

    if (offset != 0)
        return -EINVAL;

    r = read(fi->fh, buf, size);
    if (r < 0)
        return -errno;

    if (r == 0) {
        int status = 0;

        if (waitpid(cfg->pids[fi->fh], &status, 0) != cfg->pids[fi->fh])
            return -ENOKEY;

        cfg->pids[fi->fh] = 0;

        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
            return -ENOKEY;
    }

    return r;
}

static int
cf_write(const char *path, const char *buf, size_t size, off_t offset,
         struct fuse_file_info *fi)
{
    ssize_t r;

    if (offset != 0)
        return -EINVAL;

    r = write(fi->fh, buf, size);
    if (r < 0)
        return -errno;

    return r;
}

static int
cf_statfs(const char *path, struct statvfs *stv)
{
    char rp[PATH_MAX];
    int r = 0;

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    r = statvfs(rp, stv);
    if (r < 0)
        return -errno;

    return 0;
}

static int
cf_release(const char *path, struct fuse_file_info *fi)
{
    struct fuse_context *ctx = fuse_get_context();
    struct config *cfg = ctx->private_data;

    if (cfg->pids[fi->fh] > 0) {
        kill(cfg->pids[fi->fh], SIGTERM);
        waitpid(cfg->pids[fi->fh], NULL, 0);
        cfg->pids[fi->fh] = 0;
    }

    return close(fi->fh);
}

static int
cf_setxattr(const char *path, const char *name, const char *value,
            size_t size, int flags)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (lsetxattr(rp, name, value, size, flags) < 0)
        return -errno;

    return 0;
}

static int
cf_getxattr(const char *path, const char *name, char *value, size_t size)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (lgetxattr(rp, name, value, size) < 0)
        return -errno;

    return 0;
}

static int
cf_listxattr(const char *path, char *list, size_t size)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (llistxattr(rp, list, size) < 0)
        return -errno;

    return 0;
}

static int
cf_removexattr(const char *path, const char *name)
{
    char rp[PATH_MAX];

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    if (lremovexattr(rp, name) < 0)
        return -errno;

    return 0;
}

static int
cf_opendir(const char *path, struct fuse_file_info *fi)
{
    char rp[PATH_MAX];
    DIR *dp = NULL;

    if (!mkrp(rp, path))
        return -ENAMETOOLONG;

    dp = opendir(rp);
    if (!dp)
        return -errno;

    fi->fh = (intptr_t) dp;
    return 0;
}

static int
cf_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset,
           struct fuse_file_info *fi)
{
    uintptr_t ip = fi->fh;
    DIR *dp = (DIR *) ip;

    for (struct dirent *de = readdir(dp); de; de = readdir(dp)) {
        if (filler(buf, de->d_name, NULL, 0) != 0)
            return -ENOMEM;
    }

    return 0;
}

static int
cf_releasedir(const char *path, struct fuse_file_info *fi)
{
    uintptr_t ip = fi->fh;
    DIR *dp = (DIR *) ip;
    int r = 0;

    if (fi->fh == 0)
        return 0;

    r = closedir(dp);
    fi->fh = 0;
    return r;
}

static int
cf_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
    const int mask = O_LARGEFILE | O_WRONLY | O_CREAT | O_TRUNC;
    const struct fuse_context *ctx = fuse_get_context();

    if (fi->flags & ~mask)
        return -EINVAL;

    fi->flags |= mask & ~O_LARGEFILE;
    return do_open(path, mode, &ctx->uid, &ctx->gid, fi);
}

static const struct fuse_operations fops = {
    .getattr = cf_getattr,
    .readlink = cf_readlink,
    .mknod = cf_mknod,
    .mkdir = cf_mkdir,
    .unlink = cf_unlink,
    .rmdir = cf_rmdir,
    .symlink = cf_symlink,
    .rename = cf_rename,
    .link = cf_link,
    .chmod = cf_chmod,
    .chown = cf_chown,
    .truncate = cf_truncate,
    .utime = cf_utime,
    .open = cf_open,
    .read = cf_read,
    .write = cf_write,
    .statfs = cf_statfs,
    .release = cf_release,
    .setxattr = cf_setxattr,
    .getxattr = cf_getxattr,
    .listxattr = cf_listxattr,
    .removexattr = cf_removexattr,
    .opendir = cf_opendir,
    .readdir = cf_readdir,
    .releasedir = cf_releasedir,
    .create = cf_create,
};

static size_t
cb(void *buffer, size_t buflen, void *data)
{
    char *str = data;
    memcpy(buffer, data, 1);
    memmove(str, &str[1], strlen(str));
    return 1;
}

static void
cfg_auto(struct config *cfg)
{
    free(cfg->pin);
    free(cfg->cfg);
}

int
main(int argc, char *argv[])
{
    struct config __attribute__((cleanup(cfg_auto))) cfg = {};
    char src[PATH_MAX] = {};
    long nfds = 0;

    if (argc == 2 && strcmp("--summary", argv[1]) == 0) {
        fprintf(stdout, "Mount an auto-decrypt pseudo-filesystem");
        return 0;
    }

    nfds = sysconf(_SC_OPEN_MAX);
    if (nfds < 1)
        return EXIT_FAILURE;

    pid_t pids[nfds];
    memset(pids, 0, sizeof(pids));

    cfg.src = src;
    cfg.pids = pids;

    for (int o; (o = getopt(argc, argv, "hdo:")) != -1; ) {
        switch (o) {
        case 'h': break;
        case 'd': break;
        case 'o':
            if (strlen(optarg) == 0)
                return EXIT_FAILURE;

            for (char *arg = optarg; *arg; ) {
                char *c = strchr(arg, ',');

                if (strncmp(arg, "pin=", 4) == 0) {
                    free(cfg.pin);

                    if (c) {
                        cfg.pin = strndup(&arg[4], c - &arg[4]);
                        memmove(arg, &c[1], strlen(&c[1]) + 1);
                    } else {
                        cfg.pin = strdup(&arg[4]);
                        *arg = 0;
                    }

                    if (!cfg.pin)
                        return EXIT_FAILURE;
                } else if (strncmp(arg, "cfg=", 4) == 0) {
                    json_auto_t *j = NULL;

                    memmove(arg, &arg[4], strlen(&arg[4]) + 1);
                    j = json_load_callback(cb, arg, JSON_DISABLE_EOF_CHECK, NULL);
                    if (!j) {
                        fprintf(stderr, "Invalid cfg value!");
                        return EXIT_FAILURE;
                    }

                    if (*arg == ',')
                        memmove(arg, &arg[1], strlen(&arg[1]) + 1);

                    free(cfg.cfg);
                    cfg.cfg = json_dumps(j, JSON_COMPACT | JSON_SORT_KEYS);
                    if (!cfg.cfg)
                        return EXIT_FAILURE;
                } else {
                    arg = c ? &c[1] : &arg[strlen(arg)];
                }
            }

            if (optarg[strlen(optarg) - 1] == ',')
                optarg[strlen(optarg) - 1] = 0;

            if (strlen(optarg) == 0)
                strcat(optarg, (cfg.pin && cfg.cfg) ? "rw" : "ro");

            fprintf(stderr, "%s\n", optarg);
            break;
        }
    }

    if (argc - optind != 2 || !realpath(argv[optind], src)) {
        fprintf(stderr, "Usage: clevis fuse [FUSE_OPS] SRC MNT\n");
        return EXIT_FAILURE;
    }

    argv[optind] = argv[optind + 1];
    argv[++optind] = NULL;
    return fuse_main(--argc, argv, &fops, &cfg);
}
