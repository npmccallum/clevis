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
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>
#include <jose/jwe.h>
#include <jose/openssl.h>

#include <openssl/rand.h>

#include <string.h>

#ifndef json_auto_t
#define json_auto_t json_t __attribute__((cleanup(json_decrefp)))

static void
json_decrefp(json_t **json)
{
    if (json) {
        json_decref(*json);
        *json = NULL;
    }
}
#endif

json_t *
tang_validate(const json_t *jws)
{
    json_auto_t *jwkset = NULL;
    json_t *keys = NULL;
    size_t sigs = 0;

    jwkset = jose_b64_decode_json_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    keys = json_object_get(jwkset, "keys");
    if (!json_is_array(keys))
        return NULL;

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *key = json_array_get(keys, i);

        if (!jose_jwk_allowed(key, true, NULL, "verify"))
            continue;

        if (!jose_jws_verify(jws, key))
            return NULL;

        sigs++;
    }

    if (sigs == 0)
        return NULL;

    return json_incref(keys);
}

bool
tang_bind(json_t *jwe, json_t *cek, const json_t *jwk, const char *url)
{
    json_auto_t *rcp = NULL;
    json_auto_t *key = NULL;

    rcp = json_pack("{s:{s:o,s:s}}", "header",
                    "jwk", json_deep_copy(jwk),
                    "clevis.url", url);
    if (!rcp)
        return false;

    key = json_deep_copy(jwk);
    if (!key)
        return false;

    if (jose_jwk_allowed(jwk, true, NULL, "deriveKey")) {
        const char *kty = NULL;

        if (json_unpack((json_t *) jwk, "{s:s}", "kty", &kty) < 0)
            return false;

        if (strcmp(kty, "EC") != 0)
            return false;

        json_object_del(key, "key_ops");
    } else if (!jose_jwk_allowed(jwk, true, NULL, "wrapKey"))
        return false;

    return jose_jwe_wrap(jwe, cek, key, json_incref(rcp));
}

static json_t *
add(const json_t *a, const json_t *b, bool inv)
{
    const EC_GROUP *grp = NULL;
    json_t *jwk = NULL;
    BN_CTX *ctx = NULL;
    EC_POINT *p = NULL;
    EC_KEY *ak = NULL;
    EC_KEY *bk = NULL;

    ak = jose_openssl_jwk_to_EC_KEY(a);
    bk = jose_openssl_jwk_to_EC_KEY(b);
    ctx = BN_CTX_new();
    if (!ak || !bk || !ctx)
        goto egress;

    grp = EC_KEY_get0_group(ak);
    if (EC_GROUP_cmp(grp, EC_KEY_get0_group(bk), ctx) != 0)
        goto egress;

    p = EC_POINT_new(grp);
    if (!p)
        goto egress;

    if (EC_POINT_copy(p, EC_KEY_get0_public_key(bk)) < 0)
        goto egress;

    if (inv) {
        if (EC_POINT_invert(grp, p, ctx) < 0)
            goto egress;
    }

    if (EC_POINT_add(grp, p, EC_KEY_get0_public_key(ak), p, ctx) < 0)
        goto egress;

    jwk = jose_openssl_jwk_from_EC_POINT(EC_KEY_get0_group(ak), p, NULL);

egress:
    BN_CTX_free(ctx);
    EC_POINT_free(p);
    EC_KEY_free(ak);
    EC_KEY_free(bk);
    return jwk;
}

bool
tang_prepare(const json_t *jwe, const json_t *rcp, json_t **req, json_t **eph)
{
    json_auto_t *hdr = NULL;
    json_auto_t *jwk = NULL;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return false;

    jwk = json_object_get(hdr, "jwk");
    if (!jwk)
        return false;

    if (jose_jwk_allowed(jwk, true, NULL, "wrapKey")) {
        json_auto_t *outer = NULL;
        json_auto_t *inner = NULL;
        json_auto_t *cek = NULL;
        json_auto_t *key = NULL;
        json_t *tmp = NULL;

        key = json_pack("{s:s}", "alg", "A128GCMKW");
        if (!key)
            return false;

        if (!jose_jwk_generate(key))
            return false;

        inner = json_deep_copy(rcp);
        if (!inner)
            return false;

        tmp = json_object_get(inner, "header");
        if (!tmp)
            return false;

        if (json_object_del(tmp, "jwk") < 0)
            return false;

        if (json_object_del(tmp, "clevis.url") < 0)
            return false;

        if (json_object_set(tmp, "tang.jwk", key) < 0)
            return false;

        tmp = json_object_get(jwe, "protected");
        if (tmp && json_object_set(inner, "protected", tmp) < 0)
            return false;

        tmp = json_object_get(jwe, "unprotected");
        if (tmp && json_object_set(inner, "unprotected", tmp) < 0)
            return false;

        outer = json_object();
        cek = json_object();
        if (!outer || !cek)
            return false;

        if (!jose_jwe_wrap(outer, cek, jwk, NULL))
            return false;

        if (!jose_jwe_encrypt_json(outer, cek, inner))
            return false;

        *req = json_incref(outer);
        *eph = json_incref(key);
        return true;
    }

    if (jose_jwk_allowed(jwk, true, NULL, "deriveKey")) {
        json_auto_t *tmp = NULL;
        json_auto_t *key = NULL;
        json_t *epk = NULL;

        epk = json_object_get(hdr, "epk");
        if (!epk)
            return false;

        tmp = json_pack("{s:s,s:O}", "kty", "EC", "crv",
                        json_object_get(jwk, "crv"));
        if (!tmp)
            return false;

        if (!jose_jwk_generate(tmp))
            return false;

        key = add(tmp, epk, false);
        if (!req)
            return false;

        *req = json_incref(key);
        *eph = json_incref(tmp);
        return true;
    }

    return false;
}

json_t *
tang_recover(const json_t *jwe, const json_t *rcp,
             const json_t *eph, const json_t *rep)
{
    json_auto_t *hdr = NULL;
    json_auto_t *jwk = NULL;

    hdr = jose_jwe_merge_header(jwe, rcp);
    if (!hdr)
        return NULL;

    jwk = json_object_get(hdr, "jwk");
    if (!jwk)
        return NULL;

    if (jose_jwk_allowed(jwk, true, NULL, "wrapKey")) {
        json_auto_t *cek = NULL;

        cek = jose_jwe_unwrap(rep, NULL, eph);
        if (!cek)
            return NULL;

        return jose_jwe_decrypt_json(rep, cek);
    }

    if (jose_jwk_allowed(jwk, true, NULL, "deriveKey")) {
        json_auto_t *exc = NULL;
        json_auto_t *rec = NULL;

        exc = jose_jwk_exchange(eph, jwk);
        if (!exc)
            return NULL;

        rec = add(rep, exc, true);
        if (!rec)
            return NULL;

        return jose_jwe_unwrap(jwe, rcp, rec);
    }

    return NULL;
}
