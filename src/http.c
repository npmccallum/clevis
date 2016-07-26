/* vim: set tabstop=8 shiftwidth=4 softtabstop=4 expandtab smarttab colorcolumn=80: */
/*
 * Copyright (c) 2016 Red Hat, Inc.
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

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

struct packet {
    size_t len;
    char buf[65507];
};

struct url {
    char    *schm;
    char    *host;
    char    *srvc;
    char    *path;
};

struct ctx {
    struct body *body;
    char *hfld;
    bool hval;
    bool done;
};

static int
on_header_field(http_parser *parser, const char *at, size_t length)
{
    struct ctx *ctx = parser->data;
    char *tmp = NULL;
    size_t len = 0;

    if (ctx->hval) {
        free(ctx->hfld);
        ctx->hfld = NULL;
        ctx->hval = false;
    }

    len = ctx->hfld ? strlen(ctx->hfld) : 0;
    if (len + length + 1 > 4096)
        return -E2BIG;

    tmp = realloc(ctx->hfld, len + length + 1);
    if (!tmp)
        return -ENOMEM;

    if (len > 0)
        strncat(tmp, at, length);
    else
        strncpy(tmp, at, length);

    ctx->hfld = tmp;
    return 0;
}

static int
on_header_value(http_parser *parser, const char *at, size_t length)
{
    struct ctx *ctx = parser->data;
    char *tmp = NULL;
    size_t len = 0;

    if (!ctx->hfld)
        return -EINVAL;

    ctx->hval = true;

    if (strcasecmp(ctx->hfld, "Content-Type") != 0)
        return 0;

    len = ctx->body->type ? strlen(ctx->body->type) : 0;
    if (len + length + 1 > 4096)
        return -E2BIG;

    tmp = realloc(ctx->body->type, len + length + 1);
    if (!tmp)
        return -ENOMEM;

    if (len > 0)
        strncat(tmp, at, length);
    else
        strncpy(tmp, at, length);

    ctx->body->type = tmp;
    return 0;
}

static int
on_headers_complete(http_parser *parser)
{
    struct ctx *ctx = parser->data;
    ctx->hval = false;
    free(ctx->hfld);
    ctx->hfld = NULL;
    return 0;
}

static int
on_body(http_parser *parser, const char *at, size_t length)
{
    struct ctx *ctx = parser->data;
    uint8_t *tmp = NULL;

    if (ctx->body->size + length > 64 * 1024)
        return -E2BIG;

    tmp = realloc(ctx->body->body, ctx->body->size + length);
    if (!tmp)
        return -ENOMEM;

    memcpy(&tmp[ctx->body->size], at, length);
    ctx->body->size += length;
    ctx->body->body = tmp;
    return 0;
}

static int
on_message_complete(http_parser *parser)
{
    struct ctx *ctx = parser->data;
    ctx->done = true;
    return 0;
}

static const http_parser_settings settings = {
    .on_header_field = on_header_field,
    .on_header_value = on_header_value,
    .on_headers_complete = on_headers_complete,
    .on_body = on_body,
    .on_message_complete = on_message_complete,
};

#define append(pkt, ...) \
    snprintf(&pkt->buf[pkt->len], sizeof(pkt->buf) - pkt->len, __VA_ARGS__)

static int
mkpkt(struct packet *pkt, const char *host, const char *path,
      const char *method, const struct header headers[],
      const struct body *in)
{
    pkt->len += append(pkt, "%s %s HTTP/1.1\r\n", method, path);
    if (pkt->len > sizeof(pkt->buf))
        return E2BIG;

    pkt->len += append(pkt, "Host: %s\r\n", host);
    if (pkt->len > sizeof(pkt->buf))
        return E2BIG;

    if (in) {
        if (in->type) {
            pkt->len += append(pkt, "Content-Type: %s\r\n", in->type);
            if (pkt->len > sizeof(pkt->buf))
                return E2BIG;
        }

        pkt->len += append(pkt, "Content-Length: %zu\r\n", in->size);
        if (pkt->len > sizeof(pkt->buf))
            return E2BIG;
    }

    if (headers) {
        for (size_t i = 0; headers[i].key && headers[i].val; i++) {
            pkt->len += append(pkt, "%s: %s\r\n",
                              headers[i].key, headers[i].val);
            if (pkt->len > sizeof(pkt->buf))
                return E2BIG;
        }
    }

    pkt->len += append(pkt, "\r\n");
    if (pkt->len > sizeof(pkt->buf))
        return E2BIG;

    if (in) {
        if (pkt->len + in->size > sizeof(pkt->buf))
            return E2BIG;

        memcpy(&pkt->buf[pkt->len], in->body, in->size);
        pkt->len += in->size;
    }

    return 0;
}

static void
url_free_contents(struct url *url)
{
    free(url->schm);
    free(url->host);
    free(url->srvc);
    free(url->path);
    memset(url, 0, sizeof(*url));
}

static int
url_parse(const char *url, struct url *out)
{
    const uint16_t mask = (1 << UF_SCHEMA) | (1 << UF_HOST) | (1 << UF_PATH);
    struct http_parser_url purl = {};

    if (http_parser_parse_url(url, strlen(url), false, &purl) != 0)
        return EINVAL;

    if ((purl.field_set & mask) != mask)
        return EINVAL;

    if (purl.field_data[UF_PATH].len > PATH_MAX)
        return EINVAL;

    out->schm = strndup(&url[purl.field_data[UF_SCHEMA].off],
                        purl.field_data[UF_SCHEMA].len);

    out->host = strndup(&url[purl.field_data[UF_HOST].off],
                        purl.field_data[UF_HOST].len);

    out->path = strndup(&url[purl.field_data[UF_PATH].off],
                        purl.field_data[UF_PATH].len);

    if (purl.field_set & (1 << UF_PORT)) {
        out->srvc = strndup(&url[purl.field_data[UF_PORT].off],
                            purl.field_data[UF_PORT].len);
    } else if (out->schm) {
        out->srvc = strdup(out->schm);
    }

    if (!out->schm || !out->host || !out->path || !out->srvc) {
        url_free_contents(out);
        return ENOMEM;
    }

    return 0;
}

int
http(const char *url, enum http_method m, const struct header headers[],
     const struct body *in, struct body *out)
{
    struct addrinfo *ais = NULL;
    const char *method = NULL;
    struct packet pkt = {};
    struct url purl = {};
    int sock = -1;
    int r = 0;

    switch (m) {
    case HTTP_DELETE: method = "DELETE"; break;
    case HTTP_GET: method = "GET"; break;
    case HTTP_POST: method = "POST"; break;
    case HTTP_PUT: method = "PUT"; break;
    default: return -ENOTSUP;
    }

    r = url_parse(url, &purl);
    if (r != 0)
        return -r;

    r = mkpkt(&pkt, purl.host, purl.path, method, headers, in);
    if (r != 0)
        return -r;

    r = getaddrinfo(purl.host, purl.srvc,
                    &(struct addrinfo) { .ai_socktype = SOCK_STREAM }, &ais);
    switch (r) {
    case 0: break;
    case EAI_AGAIN: return -EAGAIN;
    case EAI_BADFLAGS: return -EINVAL;
    case EAI_FAMILY: return -ENOTSUP;
    case EAI_MEMORY: return -ENOMEM;
    case EAI_SERVICE: return -EINVAL;
    default: return -EIO;
    }

    for (const struct addrinfo *ai = ais; ai; ai = ai->ai_next) {
        struct ctx ctx = { .body = out };
        http_parser parser = {};

        close(sock);

        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0)
            continue;

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) != 0)
            continue;

        if (send(sock, pkt.buf, pkt.len, 0) != (ssize_t) pkt.len)
            break;

        http_parser_init(&parser, HTTP_RESPONSE);
        parser.data = &ctx;

        for (ssize_t x = 1; x > 0 && !ctx.done; ) {
            size_t sz = 0;

            x = recv(sock, &pkt.buf[pkt.len], sizeof(pkt.buf) - pkt.len, 0);
            if (x < 0)
                break;

            pkt.len += x;

            sz = http_parser_execute(&parser, &settings, pkt.buf, x);
            if (parser.http_errno != 0) {
                fprintf(stderr, "Fatal error: %s: %s\n",
                        http_errno_name(parser.http_errno),
                        http_errno_description(parser.http_errno));
                break;
            }

            pkt.buf[pkt.len] -= sz;
            memmove(pkt.buf, &pkt.buf[sz], pkt.len);
        }

        if (ctx.done)
            errno = -parser.status_code;

        free(ctx.body);
        break;
    }

    freeaddrinfo(ais);
    close(sock);
    return -errno;
}
