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

#pragma once

#include <jansson.h>

/**
 * Validates an advertisement.
 *
 * This function ensures that the advertisment has all required attributes
 * and that it is signed by all included signing keys. It returns an array
 * of the keys inside the advertisement payload on success.
 */
json_t *
adv_vld(const json_t *jws);

/**
 * Generate a new binding key and return state.
 *
 * The new binding key will be bound to jwk.
 * The jwkt will be filled in with the new key data.
 *
 * Returns the state to be used in the rec_req() and rec_rep() functions.
 */
json_t *
adv_rep(const json_t *jwk, json_t *jwkt);

/**
 * Creates the recovery request from the state.
 *
 * DO NOT persist state after calling this function as it may be modified.
 *
 * Returns the recovery request.
 */
json_t *
rec_req(json_t *state);

/**
 * Recovers the key after a recovery request.
 *
 * DO NOT persist state after calling this function as it may be modified.
 *
 * Returns the recovered JWK (the same key as jwkt after adv_rep()).
 */
json_t *
rec_rep(json_t *state, const json_t *rep);
