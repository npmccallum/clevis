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

#include "tang.h"
#include <jose/b64.h>
#include <jose/jwk.h>
#include <jose/jws.h>
#include <jose/jwe.h>
#include <jose/openssl.h>

#include <openssl/rand.h>

#include <string.h>

static json_t *
anon(const json_t *jwk, json_t *jwkt, size_t bytes)
{
    const int iter = 1000;
    json_t *state = NULL;
    json_t *req = NULL;
    EC_POINT *k = NULL;
    BN_CTX *ctx = NULL;
    EC_KEY *lcl = NULL;
    EC_KEY *rem = NULL;
    char *pass = NULL;
    uint8_t ky[bytes];
    uint8_t st[bytes];

    rem = jose_openssl_jwk_to_EC_KEY(jwk);
    if (!rem)
        goto egress;

    lcl = EC_KEY_new();
    if (!lcl)
        goto egress;

    if (EC_KEY_set_group(lcl, EC_KEY_get0_group(rem)) <= 0)
        goto egress;

    if (EC_KEY_generate_key(lcl) <= 0)
        goto egress;

    k = EC_POINT_new(EC_KEY_get0_group(rem));
    if (!k)
        goto egress;

    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    if (EC_POINT_mul(EC_KEY_get0_group(rem), k, NULL,
                     EC_KEY_get0_public_key(rem),
                     EC_KEY_get0_private_key(lcl), ctx) <= 0)
        goto egress;

    if (RAND_bytes(st, sizeof(st)) <= 0)
        goto egress;

    pass = EC_POINT_point2hex(EC_KEY_get0_group(lcl), k,
                              POINT_CONVERSION_COMPRESSED, ctx);
    if (!pass)
        goto egress;

    if (PKCS5_PBKDF2_HMAC(pass, strlen(pass), st, bytes, iter,
                          EVP_sha256(), bytes, ky) <= 0)
        goto egress;

    req = jose_openssl_jwk_from_EC_POINT(EC_KEY_get0_group(lcl),
                                         EC_KEY_get0_public_key(lcl), NULL);
    if (!req)
        goto egress;

    if (json_object_set_new(req, "kid",
                            json_deep_copy(json_object_get(jwk, "kid"))) != 0)
        goto egress;

    state = json_pack("{s:i,s:s,s:o,s:o,s:o,s:O}",
                      "iter", iter, "hash", "sha256",
                      "jwk", json_deep_copy(jwk),
                      "jwkt", json_deep_copy(jwkt),
                      "salt", jose_b64_encode_json(st, bytes),
                      "req", req);

    if (json_object_set_new(jwkt, "k", jose_b64_encode_json(ky, bytes)) != 0) {
        json_decref(state);
        state = NULL;
    }

egress:
    memset(ky, 0, sizeof(ky));
    memset(st, 0, sizeof(st));
    OPENSSL_free(pass);
    EC_POINT_free(k);
    BN_CTX_free(ctx);
    EC_KEY_free(lcl);
    EC_KEY_free(rem);
    json_decref(req);
    return state;
}

static json_t *
wrap(const json_t *jwk, json_t *jwkt, size_t bytes)
{
    uint8_t ky[bytes * 3];
    json_t *state = NULL;
    json_t *jwe = NULL;
    json_t *cek = NULL;
    json_t *pt = NULL;

    if (RAND_bytes(ky, sizeof(ky)) <= 0)
        return false;

    if (json_object_set_new(jwkt, "k", jose_b64_encode_json(ky, bytes)) != 0)
        goto egress;

    for (size_t i = 0; i < bytes; i++)
        ky[i] ^= ky[bytes + i];

    pt = json_pack("{s:o,s:o}", "key", jose_b64_encode_json(ky, bytes),
                   "bid", jose_b64_encode_json(&ky[bytes * 2], bytes));
    if (!pt)
        goto egress;

    jwe = json_pack("{s:{s:o}}", "protected",
                    "kid", json_deep_copy(json_object_get(jwk, "kid")));
    cek = json_object();
    if (!jwe || !cek)
        goto egress;

    if (!jose_jwe_wrap(jwe, cek, jwk, NULL))
        goto egress;

    if (!jose_jwe_encrypt_json(jwe, cek, pt))
        goto egress;

    state = json_pack("{s:O,s:o,s:o,s:O,s:o}",
                      "jwe", jwe,
                      "jwk", json_deep_copy(jwk),
                      "jwkt", json_deep_copy(jwkt),
                      "bid", json_object_get(pt, "bid"),
                      "otp", jose_b64_encode_json(&ky[bytes], bytes));

    if (json_object_del(json_object_get(state, "jwkt"), "k") != 0) {
        json_decref(state);
        state = NULL;
    }

egress:
    memset(ky, 0, sizeof(ky));
    json_decref(jwe);
    json_decref(cek);
    json_decref(pt);
    return state;
}

json_t *
adv_vld(const json_t *jws)
{
    json_t *jwkset = NULL;
    json_t *keys = NULL;
    size_t sigs = 0;

    jwkset = jose_b64_decode_json_load(json_object_get(jws, "payload"));
    if (!jwkset)
        return NULL;

    keys = json_object_get(jwkset, "keys");
    if (!json_is_array(keys))
        goto error;

    for (size_t i = 0; i < json_array_size(keys); i++) {
        json_t *key = json_array_get(keys, i);
        const char *kid = NULL;
        char *thp = NULL;
        bool eq = false;

        if (json_unpack(key, "{s:s}", "kid", &kid) != 0)
            goto error;

        thp = jose_jwk_thumbprint(key, "sha256");
        if (!thp)
            goto error;

        eq = strcmp(thp, kid) == 0;
        free(thp);
        if (!eq)
            goto error;

        if (!jose_jwk_allowed(key, true, NULL, "verify"))
            continue;

        if (!jose_jws_verify(jws, key))
            goto error;

        sigs++;
    }

    if (sigs == 0)
        goto error;

    keys = json_incref(keys);
    json_decref(jwkset);
    return keys;

error:
    json_decref(jwkset);
    return NULL;
}

json_t *
adv_rep(const json_t *jwk, json_t *jwkt)
{
    const char *kty = NULL;
    int bytes = 0;

    if (json_unpack(jwkt, "{s:s,s:i}", "kty", &kty, "bytes", &bytes))
        return NULL;

    if (strcmp(kty, "oct") != 0 || bytes <= 0)
        return NULL;

    if (json_object_del(jwkt, "bytes") < 0)
        return NULL;

    if (jose_jwk_allowed(jwk, true, NULL, "tang.derive"))
        return anon(jwk, jwkt, bytes);

    if (jose_jwk_allowed(jwk, true, NULL, "wrapKey"))
        return wrap(jwk, jwkt, bytes);

    return NULL;
}

static void __attribute__((constructor))
constructor(void)
{
    static jose_jwk_op_t tang = {
        .pub = "tang.derive",
        .prv = "tang.recover",
        .use = "tang"
    };

    jose_jwk_register_op(&tang);
}

static json_t *
req_anon(json_t *state)
{
    EC_POINT *p = NULL;
    BN_CTX *ctx = NULL;
    EC_KEY *eph = NULL;
    EC_KEY *key = NULL;
    json_t *jwk = NULL;
    json_t *req = NULL;

    /* Unpack state values. */
    if (json_unpack(state, "{s:o}", "req", &jwk) != 0)
        return NULL;

    key = jose_openssl_jwk_to_EC_KEY(jwk);
    if (!key)
        goto egress;

    /* Generate the ephemeral key. */
    eph = EC_KEY_new();
    if (!eph)
        goto egress;

    if (EC_KEY_set_group(eph, EC_KEY_get0_group(key)) <= 0)
        goto egress;

    if (EC_KEY_generate_key(eph) <= 0)
        goto egress;

    if (json_object_set_new(state, "eph",
                            jose_openssl_jwk_from_EC_KEY(eph)) != 0)
        goto egress;


    /* Perform point addition. */
    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    p = EC_POINT_new(EC_KEY_get0_group(key));
    if (!p)
        goto egress;

    if (EC_POINT_add(EC_KEY_get0_group(key), p,
                     EC_KEY_get0_public_key(eph),
                     EC_KEY_get0_public_key(key), ctx) <= 0)
        goto egress;

    /* Create output request. */
    req = jose_openssl_jwk_from_EC_POINT(EC_KEY_get0_group(key), p, NULL);
    if (!req)
        goto egress;

    if (json_object_update_missing(req, jwk) != 0) {
        json_decref(req);
        req = NULL;
    }

egress:
    EC_POINT_free(p);
    EC_KEY_free(eph);
    EC_KEY_free(key);
    BN_CTX_free(ctx);
    return req;
}

static json_t *
req_wrap(json_t *state)
{
    const json_t *jwk = NULL;
    const json_t *jwe = NULL;
    uint8_t *otp = NULL;
    uint8_t *xor = NULL;
    json_t *cek = NULL;
    json_t *pt = NULL;
    json_t *ct = NULL;
    size_t len = 0;

    otp = jose_b64_decode_json(json_object_get(state, "otp"), &len);
    if (!otp)
        return NULL;

    xor = malloc(len);
    if (!xor) {
        memset(otp, 0, len);
        free(otp);
        return NULL;
    }

    jwk = json_object_get(state, "jwk");
    jwe = json_object_get(state, "jwe");
    if (!jwk || !jwe)
        goto error;

    if (RAND_bytes(xor, len) <= 0)
        goto error;

    for (size_t i = 0; i < len; i++)
        otp[i] ^= xor[i];

    pt = json_pack("{s:O,s:o}", "jwe", jwe,
                   "otp", jose_b64_encode_json(xor, len));
    if (!pt)
        goto error;

    ct = json_pack("{s:{s:O}}", "protected",
                   "kid", json_object_get(jwk, "kid"));
    if (!ct)
        goto error;

    cek = json_object();
    if (!cek)
        goto error;

    if (!jose_jwe_wrap(ct, cek, jwk, NULL))
        goto error;

    if (!jose_jwe_encrypt_json(ct, cek, pt))
        goto error;

    if (json_object_set_new(state, "tmp", jose_b64_encode_json(otp, len)) != 0)
        goto error;

    memset(otp, 0, len);
    memset(xor, 0, len);
    json_decref(cek);
    json_decref(pt);
    free(otp);
    free(xor);
    return ct;

error:
    memset(otp, 0, len);
    memset(xor, 0, len);
    json_decref(cek);
    json_decref(pt);
    json_decref(ct);
    free(otp);
    free(xor);
    return NULL;
}

static json_t *
kdf(json_t *state, const EC_GROUP *grp, const EC_POINT *p, BN_CTX *ctx)
{
    static const struct {
        const char *name;
        const EVP_MD *(*md)(void);
    } table[] = {
        { "sha256", EVP_sha256 },
        {}
    };

    const EVP_MD *md = NULL;
    const char *salt = NULL;
    const char *hash = NULL;
    json_t *out = NULL;
    uint8_t *ky = NULL;
    uint8_t *st = NULL;
    char *pass = NULL;
    size_t len = 0;
    int iter = 1;

    if (json_unpack(state, "{s:s,s:s,s:i}",
                    "hash", &hash, "salt", &salt, "iter", &iter) != 0)
        return NULL;

    for (size_t i = 0; table[i].name && !md; i++) {
        if (strcmp(table[i].name, hash) == 0)
            md = table[i].md();
    }

    if (!md)
        return NULL;

    st = jose_b64_decode(salt, &len);
    if (!st)
        return NULL;

    ky = malloc(len);
    if (!ky)
        goto egress;

    pass = EC_POINT_point2hex(grp, p, POINT_CONVERSION_COMPRESSED, ctx);
    if (!pass)
        goto egress;

    if (PKCS5_PBKDF2_HMAC(pass, strlen(pass), st, len, iter, md, len, ky) <= 0)
        goto egress;

    out = json_deep_copy(json_object_get(state, "jwkt"));
    if (out) {
        if (json_object_set_new(out, "k", jose_b64_encode_json(ky, len)) < 0) {
            json_decref(out);
            out = NULL;
        }
    }

egress:
    memset(st, 0, len);

    if (ky)
        memset(ky, 0, len);

    if (pass)
        memset(pass, 0, strlen(pass));

    OPENSSL_free(pass);
    free(st);
    free(ky);
    return out;
}

static json_t *
rep_anon(json_t *state, const json_t *rep)
{
    const json_t *tmp = NULL;
    const json_t *jwk = NULL;
    EC_POINT *p = NULL;
    EC_KEY *eph = NULL;
    EC_KEY *key = NULL;
    EC_KEY *rpl = NULL;
    BN_CTX *ctx = NULL;
    json_t *out = NULL;

    ctx = BN_CTX_new();
    if (!ctx)
        goto egress;

    /* Load all the keys required for recovery. */
    if (json_unpack(state, "{s:o,s:o}", "eph", &tmp, "jwk", &jwk) != 0)
        goto egress;

    eph = jose_openssl_jwk_to_EC_KEY(tmp);
    key = jose_openssl_jwk_to_EC_KEY(jwk);
    rpl = jose_openssl_jwk_to_EC_KEY(rep);
    if (!eph || !key || !rpl)
        goto egress;

    if (EC_GROUP_cmp(EC_KEY_get0_group(rpl), EC_KEY_get0_group(eph), ctx) != 0)
        goto egress;

    /* Perform recovery. */
    p = EC_POINT_new(EC_KEY_get0_group(eph));
    if (!p)
        goto egress;

    if (EC_POINT_mul(EC_KEY_get0_group(key), p, NULL,
                     EC_KEY_get0_public_key(key),
                     EC_KEY_get0_private_key(eph), ctx) <= 0)
        goto egress;

    if (EC_POINT_invert(EC_KEY_get0_group(key), p, ctx) <= 0)
        goto egress;

    if (EC_POINT_add(EC_KEY_get0_group(key), p, p,
                     EC_KEY_get0_public_key(rpl), ctx) <= 0)
        goto egress;

    /* Create output key. */
    out = kdf(state, EC_KEY_get0_group(key), p, ctx);

egress:
    EC_POINT_free(p);
    EC_KEY_free(eph);
    EC_KEY_free(key);
    EC_KEY_free(rpl);
    BN_CTX_free(ctx);
    return out;
}

static json_t *
rep_wrap(json_t *state, const json_t *rep)
{
    uint8_t *otp = NULL;
    uint8_t *key = NULL;
    json_t *out = NULL;
    size_t otpl = 0;
    size_t keyl = 0;

    otp = jose_b64_decode_json(json_object_get(state, "tmp"), &otpl);
    if (!otp)
        return NULL;

    key = jose_b64_decode_json(json_object_get(rep, "k"), &keyl);
    if (!key) {
        memset(otp, 0, otpl);
        free(otp);
        return NULL;
    }

    if (otpl != keyl)
        goto egress;

    for (size_t i = 0; i < otpl; i++)
        key[i] ^= otp[i];

    out = json_deep_copy(json_object_get(state, "jwkt"));
    if (out) {
        if (json_object_set_new(out, "k",
                                jose_b64_encode_json(key, keyl)) < 0) {
            json_decref(out);
            out = NULL;
        }
    }

egress:
    memset(otp, 0, otpl);
    memset(key, 0, keyl);
    free(otp);
    free(key);
    return out;
}

json_t *
rec_req(json_t *state)
{
    json_t *out = NULL;

    out = req_wrap(state);
    return out ? out : req_anon(state);
}

json_t *
rec_rep(json_t *state, const json_t *rep)
{
    json_t *jwk = NULL;

    jwk = rep_wrap(state, rep);
    return jwk ? jwk : rep_anon(state, rep);
}
