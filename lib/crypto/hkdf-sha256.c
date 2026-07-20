// SPDX-License-Identifier: GPL-2.0-only
/*
 * HKDF-SHA256 library functions (RFC 5869)
 *
 * Derived from fs/crypto/hkdf.c
 * Copyright 2019 Google LLC
 */

#include <crypto/hkdf.h>
#include <linux/string.h>

#define HKDF_EXTRACT		hkdf_sha256_extract
#define HKDF_EXPAND		hkdf_sha256_expand
#define HMAC_KEY		hmac_sha256_key
#define HMAC_CTX		hmac_sha256_ctx
#define HMAC_PREPAREKEY		hmac_sha256_preparekey
#define HMAC_INIT		hmac_sha256_init
#define HMAC_UPDATE		hmac_sha256_update
#define HMAC_FINAL		hmac_sha256_final
#define HMAC_USINGRAWKEY	hmac_sha256_usingrawkey
#define HKDF_HASHLEN		SHA256_DIGEST_SIZE
#include "hkdf-template.h"
