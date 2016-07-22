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

#include "sss_alg.h"
#include <jose/b64.h>
#include <openssl/bn.h>

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define BIGNUM_auto __attribute__((cleanup(BN_cleanup))) BIGNUM

static void
clear_free(void *mem, size_t len)
{
    if (!mem)
        return;

    memset(mem, 0, len);
    free(mem);
}

static BIGNUM *
bn_decode(const uint8_t buf[], size_t len)
{
    return BN_bin2bn(buf, len, NULL);
}

static BIGNUM *
bn_decode_json(const json_t *json)
{
    uint8_t *buf = NULL;
    BIGNUM *bn = NULL;
    size_t len = 0;

    buf = jose_b64_decode_json(json, &len);
    if (!buf)
        return NULL;

    bn = bn_decode(buf, len);

    clear_free(buf, len);
    return bn;
}

static bool
bn_encode(const BIGNUM *bn, uint8_t buf[], size_t len)
{
    int bytes = 0;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    bytes = BN_num_bytes(bn);
    if (bytes < 0 || bytes > (int) len)
        return false;

    memset(buf, 0, len);
    return BN_bn2bin(bn, &buf[len - bytes]) > 0;
}

static json_t *
bn_encode_json(const BIGNUM *bn, size_t len)
{
    uint8_t *buf = NULL;
    json_t *out = NULL;

    if (!bn)
        return false;

    if (len == 0)
        len = BN_num_bytes(bn);

    if ((int) len < BN_num_bytes(bn))
        return false;

    buf = malloc(len);
    if (buf) {
        if (bn_encode(bn, buf, len))
            out = jose_b64_encode_json(buf, len);

        clear_free(buf, len);
    }

    return out;
}

static void
BN_cleanup(BIGNUM **bnp)
{
    if (bnp)
        BN_clear_free(*bnp);
}

json_t *
sss_generate(size_t key_bytes, size_t threshold)
{
    BIGNUM_auto *p = NULL;
    BIGNUM_auto *e = NULL;
    json_t *sss = NULL;

    if (key_bytes == 0 || threshold < 1)
        return NULL;

    sss = json_pack("{s:i,s:[]}", "t", threshold, "e");
    if (!sss)
        return NULL;

    p = BN_new();
    e = BN_new();
    if (!p || !e)
        goto error;

    if (!BN_generate_prime(p, key_bytes * 8, 1, NULL, NULL, NULL, NULL))
        goto error;

    if (json_object_set_new(sss, "p", bn_encode_json(p, key_bytes)) != 0)
        goto error;

    for (size_t i = 0; i < threshold; i++) {
        if (BN_rand_range(e, p) <= 0)
            goto error;

        if (json_array_append_new(json_object_get(sss, "e"),
                                  bn_encode_json(e, key_bytes)))
            goto error;
    }

    return sss;

error:
    json_decref(sss);
    return NULL;
}

json_t *
sss_point(const json_t *sss)
{
    BIGNUM_auto *tmp = NULL;
    BIGNUM_auto *xx = NULL;
    BIGNUM_auto *yy = NULL;
    BIGNUM_auto *pp = NULL;
    json_t *p = NULL;
    json_int_t t = 0;

    if (json_unpack((json_t *) sss, "{s:I,s:o}", "t", &t, "p", &p) != 0)
        return NULL;

    pp = bn_decode_json(p);
    xx = BN_new();
    yy = BN_new();
    tmp = BN_new();
    if (!pp || !xx || !yy || !tmp)
        return NULL;

    if (BN_rand_range(xx, pp) <= 0)
        return NULL;

    if (BN_zero(yy) <= 0)
        return NULL;

    for (json_int_t i = 0; i < t; i++) {
        BIGNUM_auto *e = NULL;

        e = bn_decode_json(json_array_get(json_object_get(sss, "e"), i));
        if (!e)
            return NULL;

        if (BN_cmp(pp, e) <= 0)
            return NULL;

        /* y += e[i] * x^i */

        if (BN_set_word(tmp, i) <= 0)
            return NULL;

        if (BN_mod_exp(tmp, xx, tmp, pp, ctx) <= 0)
            return NULL;

        if (BN_mod_mul(tmp, e, tmp, pp, ctx) <= 0)
            return NULL;

        if (BN_mod_add(yy, yy, tmp, pp, ctx) <= 0)
            return NULL;
    }

    return bn_encode_json(yy, jose_b64_dlen(json_string_length(p)));
}

json_t *
sss_recover(const json_t *p, const json_t *points)
{
    BIGNUM_auto *acc = BN_new();
    BIGNUM_auto *tmp = BN_new();
    BIGNUM_auto *k = BN_new();
    BIGNUM_auto *pp = NULL;
    json_t *pnto = NULL;
    size_t i = 0;

    if (!acc || !tmp || !k)
        return NULL;

    pp = bn_decode_json(p);
    if (!pp)
        return NULL;

    if (BN_zero(k) <= 0)
        return NULL;

    json_array_foreach(points, i, pnto) {
        BIGNUM_auto *xo = NULL; /* Outer X */
        BIGNUM_auto *yo = NULL; /* Outer Y */
        json_t *pnti = NULL;
        size_t j = 0;

        xo = bn_decode_json(json_array_get(pnto, 0));
        yo = bn_decode_json(json_array_get(pnto, 1));
        if (!xo || !yo)
            return NULL;

        if (BN_one(acc) <= 0)
            return NULL;

        json_array_foreach(points, j, pnti) {
            BIGNUM_auto *xi = NULL; /* Inner X */

            if (pnto == pnti)
                continue;

            xi = bn_decode_json(json_array_get(pnti, 0));
            if (!xi)
                return NULL;

            /* acc *= (0 - xi) / (xo - xi) */

            if (BN_zero(tmp) <= 0)
                return NULL;

            if (BN_mod_sub(tmp, tmp, xi, pp, ctx) <= 0)
                return NULL;

            if (BN_mod_mul(acc, acc, tmp, pp, ctx) <= 0)
                return NULL;

            if (BN_mod_sub(tmp, xo, xi, pp, ctx) <= 0)
                return NULL;

            if (BN_mod_inverse(tmp, tmp, pp, ctx) != tmp)
                return NULL;

            if (BN_mod_mul(acc, acc, tmp, pp, ctx) <= 0)
                return NULL;
        }

        /* k += acc * y[i] */

        if (BN_mod_mul(acc, acc, yo, pp, ctx) <= 0)
            return NULL;

        if (BN_mod_add(k, k, acc, pp, ctx) <= 0)
            return NULL;
    }

    return bn_encode_json(k, jose_b64_dlen(json_string_length(p)));
}
