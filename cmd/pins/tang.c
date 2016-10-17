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

#include "libtang.h"
#include "libhttp.h"

#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jwe.h>

#include <string.h>
#include <time.h>

#include <errno.h>

static int
http_json(const char *url, const char *sfx, enum http_method method,
          char *type, const json_t *req, char *accept, json_t **rep)
{
    struct http_msg hreq = {
        .head = (struct http_head[]) {
            { "Accept", accept },
            { type ? "Content-Type" : NULL, type ? type : NULL },
            {}
        },
    };

    struct http_msg *hrep = NULL;
    char full[8192] = {};
    int r = 0;

    if (snprintf(full, sizeof(full), "%s/%s", url, sfx) > (int) sizeof(full))
        return -E2BIG;

    if (req) {
        hreq.body = (uint8_t *) json_dumps(req, JSON_SORT_KEYS | JSON_COMPACT);
        if (!hreq.body)
            return -ENOMEM;

        hreq.size = strlen((char *) hreq.body);
    }

    r = http(full, method, &hreq, &hrep);
    if (hreq.body)
        memset(hreq.body, 0, hreq.size);
    free(hreq.body);
    if (r != 200) {
        http_msg_free(hrep);
        return r;
    }

    if (hrep->head) {
        for (size_t i = 0; hrep->head[i].key && hrep->head[i].val; i++) {
            if (strcasecmp("Content-Type", hrep->head[i].val) != 0)
                continue;

            if (strcasecmp(accept, hrep->head[i].val) != 0) {
                http_msg_free(hrep);
                return -EBADMSG;
            }
        }
    }

    *rep = json_loadb((char *) hrep->body, hrep->size, 0, NULL);

    http_msg_free(hrep);
    return *rep ? 200 : -EBADMSG;
}

static jose_buf_t *
readkey(FILE *file)
{
    jose_buf_auto_t *out = NULL;

    while (!feof(file)) {
        jose_buf_t *tmp = NULL;
        uint8_t buf[4096];
        size_t r = 0;

        r = fread(buf, 1, sizeof(buf), file);
        if (ferror(file))
            return NULL;

        tmp = jose_buf(out ? out->size : 0 + r, JOSE_BUF_FLAG_WIPE);
        if (!tmp)
            return NULL;

        if (out)
            memcpy(tmp->data, out->data, out->size);

        memcpy(&tmp->data[out ? out->size : 0], buf, r);
        jose_buf_decref(out);
        out = tmp;
    }

    return jose_buf_incref(out);
}

static json_t *
load_adv(const char *filename)
{
    json_auto_t *keys = NULL;
    json_auto_t *adv = NULL;
    FILE *file = NULL;

    file = fopen(filename, "r");
    if (!file)
        return NULL;

    adv = json_loadf(file, 0, NULL);
    fclose(file);

    keys = adv_vld(adv);
    return keys ? json_incref(adv) : NULL;
}

static json_t *
dnld_adv(const char *url)
{
    json_auto_t *keys = NULL;
    json_auto_t *adv = NULL;
    json_t *jwk = NULL;
    FILE *tty = NULL;
    char yn = 'x';
    size_t i = 0;
    int r = 0;

    r = http_json(url, "adv", HTTP_GET, NULL, NULL,
                  "application/jose+json", &adv);
    if (r != 200)
        return NULL;

    keys = adv_vld(adv);
    if (!keys)
        goto egress;

    tty = fopen("/dev/tty", "a+");
    if (!tty)
        goto egress;

    fprintf(tty, "The advertisement is signed with the following keys:\n");

    json_array_foreach(keys, i, jwk) {
        if (!jose_jwk_allowed(jwk, true, "verify"))
            continue;

        fprintf(tty, "\t%s\n", json_string_value(json_object_get(jwk, "kid")));
    }

    while (!strchr("YyNn", yn)) {
        fprintf(tty, "\nDo you wish to trust the advertisement? [yN] ");
        if (fread(&yn, 1, 1, tty) != 1)
            break;
    }

egress:
    if(tty)
        fclose(tty);

    if (strchr("Yy", yn))
        return json_incref(adv);

    return NULL;
}

static json_t *
select_jwk(json_t *jws)
{
    json_auto_t *jwkset = NULL;
    json_t *jwk = NULL;
    size_t i = 0;

    jwkset = jose_b64_decode_json_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    json_array_foreach(json_object_get(jwkset, "keys"), i, jwk) {
        if (jose_jwk_allowed(jwk, true, "deriveKey"))
            return json_incref(jwk);
    }

    return NULL;
}

static int
encrypt(int argc, char *argv[])
{
    jose_buf_auto_t *key = NULL;
    json_auto_t *jws = NULL;
    json_auto_t *cfg = NULL;
    json_auto_t *jwk = NULL;
    json_auto_t *jwe = NULL;
    json_auto_t *cek = NULL;
    json_auto_t *ste = NULL;
    const char *url = NULL;

    cfg = json_loads(argv[2], 0, NULL);
    if (!cfg) {
        fprintf(stderr, "Error parsing configuration!\n");
        return EXIT_FAILURE;
    }

    key = readkey(stdin);
    if (!key) {
        fprintf(stderr, "Error reading key!\n");
        json_decref(cfg);
        return EXIT_FAILURE;
    }

    if (json_unpack(cfg, "{s:s,s?o}", "url", &url, "adv", &jws) != 0) {
        fprintf(stderr, "Invalid configuration!\n");
        return EXIT_FAILURE;
    }

    if (json_is_string(jws))
        jws = load_adv(json_string_value(jws));
    else if (!json_is_object(jws))
        jws = dnld_adv(url);
    else {
        json_t *keys = adv_vld(jws);
        if (!keys) {
            fprintf(stderr, "Specified advertisement is invalid!\n");
            return EXIT_FAILURE;
        }

        json_decref(keys);
    }

    jwk = select_jwk(jws);
    if (!jwk) {
        fprintf(stderr, "Error selecting remote public key!\n");
        return EXIT_FAILURE;
    }

    cek = json_pack("{s:s,s:i}", "kty", "oct", "bytes", 32);
    if (!cek)
        return EXIT_FAILURE;

    ste = adv_rep(jwk, cek);
    if (!ste) {
        fprintf(stderr, "Error creating binding!\n");
        return EXIT_FAILURE;
    }

    jwe = json_pack("{s:{s:s,s:s},s:{s:{s:s,s:O,s:O}}}",
                    "protected",
                        "alg", "dir",
                        "clevis.pin", "tang",
                    "unprotected",
                        "clevis.pin.tang",
                            "url", url,
                            "ste", ste,
                            "adv", jws);
    if (!jwe) {
        fprintf(stderr, "Error creating JWE template!\n");
        return EXIT_FAILURE;
    }

    if (!jose_jwe_encrypt(jwe, cek, key->data, key->size)) {
        fprintf(stderr, "Error encrypting key!\n");
        return EXIT_FAILURE;
    }

    if (json_dumpf(jwe, stdout, JSON_SORT_KEYS | JSON_COMPACT) != 0)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static int
decrypt(int argc, char *argv[])
{
    jose_buf_auto_t *key = NULL;
    json_auto_t *jwe = NULL;
    json_auto_t *req = NULL;
    json_auto_t *rep = NULL;
    json_auto_t *cek = NULL;
    const char *url = NULL;
    json_t *ste = NULL;
    char *type = NULL;
    int r = 0;

    jwe = json_loadf(stdin, 0, NULL);
    if (!jwe)
        return EXIT_FAILURE;

    if (json_unpack(jwe, "{s:{s:{s:s,s:o}}}", "unprotected", "clevis.pin.tang",
                    "url", &url, "ste", &ste) != 0)
        return EXIT_FAILURE;

    req = rec_req(ste);
    if (!req)
        return EXIT_FAILURE;

    if (json_object_get(req, "kty"))
        type = "application/jwk+json";
    else
        type = "application/jose+json";

    r = http_json(url, "rec", HTTP_POST,
                  type, req, "application/jwk+json", &rep);
    if (r != 200)
        return EXIT_FAILURE;

    cek = rec_rep(ste, rep);
    if (!cek)
        return EXIT_FAILURE;

    key = jose_jwe_decrypt(jwe, cek);
    if (!key)
        return EXIT_FAILURE;

    if (fwrite(key->data, key->size, 1, stdout) != 1)
        return EXIT_FAILURE;

    return EXIT_SUCCESS;
}

static double
curtime(void)
{
    struct timespec ts = {};
    double out = 0;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) == 0)
        out = ((double) ts.tv_sec) + ((double) ts.tv_nsec) / 1000000000L;

    return out;
}

static void
dump_perf(json_t *time)
{
    const char *key = NULL;
    bool first = true;
    json_t *val = 0;

    json_object_foreach(time, key, val) {
        int v = 0;

        if (!first)
            printf(" ");
        else
            first = false;

        if (json_is_integer(val))
            v = json_integer_value(val);
        else if (json_is_real(val))
            v = json_real_value(val) * 1000000;

        printf("%s=%d", key, v);
    }
}

static bool
nagios_recover(const char *url, const json_t *jwk,
               size_t *sig, size_t *rec, json_t *time)
{
    const char *kid = NULL;
    json_auto_t *state = NULL;
    json_auto_t *bef = NULL;
    json_auto_t *aft = NULL;
    json_auto_t *req = NULL;
    json_auto_t *rep = NULL;
    char *type = NULL;
    bool ret = false;
    double s = 0;
    double e = 0;
    int r = 0;

    if (jose_jwk_allowed(jwk, true, "verify")) {
        *sig += 1;
        return true;
    }

    if (!jose_jwk_allowed(jwk, true, "deriveKey"))
        return true;

    bef = json_pack("{s:s,s:i}", "kty", "oct", "bytes", 16);
    if (!bef) {
        printf("Error creating JWK template!\n");
        return false;
    }

    state = adv_rep(jwk, bef);
    if (!state) {
        printf("Error creating binding!\n");
        return false;
    }

    req = rec_req(state);
    if (!req) {
        printf("Error preparing recovery request!\n");
        return false;
    }

    if (json_object_get(req, "kty"))
        type = "application/jwk+json";
    else
        type = "application/jose+json";

    s = curtime();
    r = http_json(url, "rec", HTTP_POST, type, req,
                  "application/jwk+json", &rep);
    e = curtime();
    if (r != 200) {
        if (r < 0)
            printf("Error performing recovery! %s\n", strerror(-r));
        else
            printf("Error performing recovery! HTTP Status %d\n", r);

        return false;
    }

    if (json_unpack((json_t *) jwk, "{s:s}", "kid", &kid) != 0)
        return false;

    if (s == 0.0 || e == 0.0 ||
        json_object_set_new(time, kid, json_real(e - s)) < 0) {
        printf("Error calculating performance metrics!\n");
        return false;
    }

    aft = rec_rep(state, rep);
    if (!aft) {
        printf("Error handing recovery result!\n");
        return false;
    }

    if (!json_equal(bef, aft)) {
        printf("Recovered key doesn't match!\n");
        return false;
    }

    *rec += 1;
    return true;
}

static int
nagios(int argc, char *argv[])
{
    enum {
        NAGIOS_OK = 0,
        NAGIOS_WARN = 1,
        NAGIOS_CRIT = 2,
        NAGIOS_UNKN = 3
    };

    json_auto_t *time = NULL;
    json_auto_t *keys = NULL;
    json_auto_t *adv = NULL;
    size_t sig = 0;
    size_t rec = 0;
    double s = 0;
    double e = 0;
    int r = 0;

    time = json_object();
    if (!time)
        return NAGIOS_CRIT;

    s = curtime();
    r = http_json(argv[2], "adv", HTTP_GET, NULL, NULL,
                  "application/jose+json", &adv);
    e = curtime();
    if (r != 200) {
        if (r < 0)
            printf("Error fetching advertisement! %s\n", strerror(-r));
        else
            printf("Error fetching advertisement! HTTP Status %d\n", r);

        return NAGIOS_CRIT;
    }

    if (s == 0.0 || e == 0.0 ||
        json_object_set_new(time, "adv", json_real(e - s)) != 0) {
        printf("Error calculating performance metrics!\n");
        return NAGIOS_CRIT;
    }

    keys = adv_vld(adv);
    if (!keys) {
        printf("Error validating advertisement!\n");
        return NAGIOS_CRIT;
    }

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *jwk = json_array_get(keys, i);
        if (!nagios_recover(argv[2], jwk, &sig, &rec, time))
            return NAGIOS_CRIT;
    }

    if (rec == 0) {
        printf("Advertisement contains no recovery keys!\n");
        return NAGIOS_CRIT;
    }

    json_object_set_new(time, "nkeys", json_integer(json_array_size(keys)));
    json_object_set_new(time, "nsigk", json_integer(sig));
    json_object_set_new(time, "nreck", json_integer(rec));

    printf("OK|");
    dump_perf(time);
    printf("\n");
    return NAGIOS_OK;
}

int
main(int argc, char *argv[])
{
    if (argc == 3 && strcmp(argv[1], "encrypt") == 0)
        return encrypt(argc, argv);

    if (argc == 2 && strcmp(argv[1], "decrypt") == 0)
        return decrypt(argc, argv);

    if (argc == 3 && strcmp(argv[1], "nagios") == 0)
        return nagios(argc, argv);

    fprintf(stderr, "Usage: %s encrypt CONFIG\n", argv[0]);
    fprintf(stderr, "   or: %s decrypt\n", argv[0]);
    fprintf(stderr, "   or: %s nagios  URL\n", argv[0]);
    return EXIT_FAILURE;
}
