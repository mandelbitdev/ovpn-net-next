// SPDX-License-Identifier: GPL-2.0-only
/*
 * HKDF-SHA384 and HKDF-SHA512 library functions (RFC 5869)
 *
 * Derived from fs/crypto/hkdf.c
 * Copyright 2019 Google LLC
 */

#include <crypto/hkdf.h>
#include <linux/string.h>

#define HKDF_EXTRACT		hkdf_sha384_extract
#define HKDF_EXPAND		hkdf_sha384_expand
#define HMAC_KEY		hmac_sha384_key
#define HMAC_CTX		hmac_sha384_ctx
#define HMAC_PREPAREKEY		hmac_sha384_preparekey
#define HMAC_INIT		hmac_sha384_init
#define HMAC_UPDATE		hmac_sha384_update
#define HMAC_FINAL		hmac_sha384_final
#define HMAC_USINGRAWKEY	hmac_sha384_usingrawkey
#define HKDF_HASHLEN		SHA384_DIGEST_SIZE
#include "hkdf-template.h"

#define HKDF_EXTRACT		hkdf_sha512_extract
#define HKDF_EXPAND		hkdf_sha512_expand
#define HMAC_KEY		hmac_sha512_key
#define HMAC_CTX		hmac_sha512_ctx
#define HMAC_PREPAREKEY		hmac_sha512_preparekey
#define HMAC_INIT		hmac_sha512_init
#define HMAC_UPDATE		hmac_sha512_update
#define HMAC_FINAL		hmac_sha512_final
#define HMAC_USINGRAWKEY	hmac_sha512_usingrawkey
#define HKDF_HASHLEN		SHA512_DIGEST_SIZE
#include "hkdf-template.h"
