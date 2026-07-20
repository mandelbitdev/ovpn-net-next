/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Implementation of HKDF ("HMAC-based Extract-and-Expand Key Derivation
 * Function"), aka RFC 5869.  See also the original paper (Krawczyk 2010):
 * "Cryptographic Extraction and Key Derivation: The HKDF Scheme".
 *
 * Derived from fs/crypto/hkdf.c
 * Copyright 2019 Google LLC
 *
 * This file is a template that generates HKDF on top of a specific HMAC
 * library.  The including file must define the following macros, and may
 * include this file multiple times to instantiate multiple variants:
 *
 *	HKDF_EXTRACT		name of the HKDF-Extract function
 *	HKDF_EXPAND		name of the HKDF-Expand function
 *	HMAC_KEY		HMAC prepared-key type, without 'struct'
 *	HMAC_CTX		HMAC context type, without 'struct'
 *	HMAC_PREPAREKEY		the hmac_*_preparekey() function
 *	HMAC_INIT		the hmac_*_init() function
 *	HMAC_UPDATE		the hmac_*_update() function
 *	HMAC_FINAL		the hmac_*_final() function
 *	HMAC_USINGRAWKEY	the hmac_*_usingrawkey() function
 *	HKDF_HASHLEN		hash digest size in bytes
 */

/*
 * HKDF-Extract (RFC 5869 section 2.2).  Compute a pseudorandom key of
 * HKDF_HASHLEN bytes from the input keying material and optional salt, and
 * prepare it as an HMAC key.
 *
 * A NULL or empty 'salt', or any all-zero salt up to the HMAC block size,
 * gives the same PRK as the RFC 5869 default salt of HKDF_HASHLEN zero bytes.
 * If 'salt' is NULL, 'salt_len' must be 0.
 */
void HKDF_EXTRACT(struct HMAC_KEY *prk, const u8 *salt, size_t salt_len,
		  const u8 *ikm, size_t ikm_len)
{
	u8 prk_bytes[HKDF_HASHLEN];

	HMAC_USINGRAWKEY(salt ? salt : (const u8 *)"", salt_len,
			 ikm, ikm_len, prk_bytes);
	HMAC_PREPAREKEY(prk, prk_bytes, sizeof(prk_bytes));
	memzero_explicit(prk_bytes, sizeof(prk_bytes));
}
EXPORT_SYMBOL_GPL(HKDF_EXTRACT);

/*
 * HKDF-Expand (RFC 5869 section 2.3).  Expand the pseudorandom key 'prk' into
 * 'okm_len' bytes of output keying material, parameterized by the
 * application-specific info, given as 'info_nsegs' segments that are
 * processed as if concatenated:
 *
 *	T(0) = empty
 *	T(n) = HMAC(PRK, T(n-1) | info | n)	for n = 1, 2, ...
 *	OKM  = first okm_len bytes of T(1) | T(2) | ...
 *
 * This is thread-safe and may be called by multiple threads in parallel.
 */
void HKDF_EXPAND(const struct HMAC_KEY *prk, const struct hkdf_seg *info,
		 size_t info_nsegs, u8 *okm, size_t okm_len)
{
	struct HMAC_CTX ctx;
	u8 counter = 1;
	u8 tmp[HKDF_HASHLEN];

	WARN_ON_ONCE(okm_len > 255 * HKDF_HASHLEN);

	for (size_t i = 0; i < okm_len; i += HKDF_HASHLEN) {
		HMAC_INIT(&ctx, prk);
		if (i != 0)
			HMAC_UPDATE(&ctx, &okm[i - HKDF_HASHLEN],
				    HKDF_HASHLEN);
		for (size_t j = 0; j < info_nsegs; j++)
			HMAC_UPDATE(&ctx, info[j].data, info[j].len);
		HMAC_UPDATE(&ctx, &counter, 1);
		if (okm_len - i < HKDF_HASHLEN) {
			HMAC_FINAL(&ctx, tmp);
			memcpy(&okm[i], tmp, okm_len - i);
			memzero_explicit(tmp, sizeof(tmp));
		} else {
			HMAC_FINAL(&ctx, &okm[i]);
		}
		counter++;
	}
}
EXPORT_SYMBOL_GPL(HKDF_EXPAND);

#undef HKDF_EXTRACT
#undef HKDF_EXPAND
#undef HMAC_KEY
#undef HMAC_CTX
#undef HMAC_PREPAREKEY
#undef HMAC_INIT
#undef HMAC_UPDATE
#undef HMAC_FINAL
#undef HMAC_USINGRAWKEY
#undef HKDF_HASHLEN
