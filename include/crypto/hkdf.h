/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * HKDF: HMAC-based Key Derivation Function (RFC 5869)
 *
 * Derived from fs/crypto/hkdf.c
 * Copyright 2019 Google LLC
 */

#ifndef _CRYPTO_HKDF_H
#define _CRYPTO_HKDF_H

#include <crypto/sha2.h>

/*
 * HKDF has two steps:
 *
 * 1. Extract: derive a pseudorandom key from input keying material and salt.
 * 2. Expand: derive output keying material from the pseudorandom key and info.
 */

/**
 * struct hkdf_seg - one segment of the HKDF-Expand 'info' parameter
 * @data: the segment data
 * @len: length of @data in bytes
 *
 * The segments are processed as if concatenated, so a composite info can be
 * passed without assembling it in a temporary buffer first.
 */
struct hkdf_seg {
	const void *data;
	size_t len;
};

/**
 * hkdf_sha256_extract() - HKDF-Extract using HMAC-SHA256
 * @prk: (output) the pseudorandom key, prepared for hkdf_sha256_expand()
 * @salt: optional non-secret salt, or NULL for the RFC 5869 default
 *	  (all-zero) salt
 * @salt_len: length of @salt in bytes (must be 0 if @salt is NULL)
 * @ikm: input keying material
 * @ikm_len: length of @ikm in bytes
 *
 * Extract a SHA256_DIGEST_SIZE-byte pseudorandom key from @ikm.  If @ikm is
 * already a pseudorandom key of that size, prepare @prk with
 * hmac_sha256_preparekey() instead.
 */
void hkdf_sha256_extract(struct hmac_sha256_key *prk,
			 const u8 *salt, size_t salt_len,
			 const u8 *ikm, size_t ikm_len);

/**
 * hkdf_sha256_expand() - HKDF-Expand using HMAC-SHA256
 * @prk: pseudorandom key from hkdf_sha256_extract() or
 *	 hmac_sha256_preparekey()
 * @info: info segments, processed as if concatenated.  Use different info for
 *	  different purposes.
 * @info_nsegs: number of segments in @info
 * @okm: (output) the output keying material
 * @okm_len: length of @okm in bytes, at most 255 * SHA256_DIGEST_SIZE
 *
 * Expand @prk into @okm_len bytes of output keying material (RFC 5869
 * section 2.3).  The same (@prk, @info) always yields the same output.
 * Different @info values yield independent outputs, but different @okm_len do
 * not: a shorter output is a truncation of a longer one.  This may be called many
 * times per @prk and is thread-safe.
 */
void hkdf_sha256_expand(const struct hmac_sha256_key *prk,
			const struct hkdf_seg *info, size_t info_nsegs,
			u8 *okm, size_t okm_len);

/**
 * hkdf_sha384_extract() - HKDF-Extract using HMAC-SHA384
 * @prk: (output) the pseudorandom key, prepared for hkdf_sha384_expand()
 * @salt: optional non-secret salt, or NULL for the RFC 5869 default
 *	  (all-zero) salt
 * @salt_len: length of @salt in bytes (must be 0 if @salt is NULL)
 * @ikm: input keying material
 * @ikm_len: length of @ikm in bytes
 *
 * SHA-384 variant of hkdf_sha256_extract().
 */
void hkdf_sha384_extract(struct hmac_sha384_key *prk,
			 const u8 *salt, size_t salt_len,
			 const u8 *ikm, size_t ikm_len);

/**
 * hkdf_sha384_expand() - HKDF-Expand using HMAC-SHA384
 * @prk: pseudorandom key from hkdf_sha384_extract() or
 *	 hmac_sha384_preparekey()
 * @info: info segments, processed as if concatenated
 * @info_nsegs: number of segments in @info
 * @okm: (output) the output keying material
 * @okm_len: length of @okm in bytes, at most 255 * SHA384_DIGEST_SIZE
 *
 * SHA-384 variant of hkdf_sha256_expand().
 */
void hkdf_sha384_expand(const struct hmac_sha384_key *prk,
			const struct hkdf_seg *info, size_t info_nsegs,
			u8 *okm, size_t okm_len);

/**
 * hkdf_sha512_extract() - HKDF-Extract using HMAC-SHA512
 * @prk: (output) the pseudorandom key, prepared for hkdf_sha512_expand()
 * @salt: optional non-secret salt, or NULL for the RFC 5869 default
 *	  (all-zero) salt
 * @salt_len: length of @salt in bytes (must be 0 if @salt is NULL)
 * @ikm: input keying material
 * @ikm_len: length of @ikm in bytes
 *
 * SHA-512 variant of hkdf_sha256_extract().
 */
void hkdf_sha512_extract(struct hmac_sha512_key *prk,
			 const u8 *salt, size_t salt_len,
			 const u8 *ikm, size_t ikm_len);

/**
 * hkdf_sha512_expand() - HKDF-Expand using HMAC-SHA512
 * @prk: pseudorandom key from hkdf_sha512_extract() or
 *	 hmac_sha512_preparekey()
 * @info: info segments, processed as if concatenated
 * @info_nsegs: number of segments in @info
 * @okm: (output) the output keying material
 * @okm_len: length of @okm in bytes, at most 255 * SHA512_DIGEST_SIZE
 *
 * SHA-512 variant of hkdf_sha256_expand().
 */
void hkdf_sha512_expand(const struct hmac_sha512_key *prk,
			const struct hkdf_seg *info, size_t info_nsegs,
			u8 *okm, size_t okm_len);

#endif /* _CRYPTO_HKDF_H */
