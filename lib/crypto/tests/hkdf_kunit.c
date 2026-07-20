// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * KUnit tests for HKDF-SHA256, HKDF-SHA384, and HKDF-SHA512
 *
 * The HKDF-SHA256 test vectors are from RFC 5869 Appendix A. RFC 5869 does not
 * provide SHA-384 or SHA-512 vectors, so those were generated with OpenSSL's
 * "openssl kdf" command (available since OpenSSL 3.0) using the same inputs as
 * the SHA-256 vectors.  See: https://docs.openssl.org/3.0/man1/openssl-kdf/
 *
 * For example, the SHA-384 vector was generated with:
 *
 * $ openssl kdf -keylen 42 -kdfopt mode:EXTRACT_AND_EXPAND \
 *     -kdfopt digest:SHA384 \
 *     -kdfopt hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b \
 *     -kdfopt hexsalt:000102030405060708090a0b0c \
 *     -kdfopt hexinfo:f0f1f2f3f4f5f6f7f8f9 HKDF
 */

#include <crypto/hkdf.h>
#include <kunit/test.h>

#define RFC5869_A1_IKM_BYTE	0x0b
#define RFC5869_A1_IKM_LEN	22
#define RFC5869_A1_SALT_START	0x00
#define RFC5869_A1_SALT_LEN	13
#define RFC5869_A1_INFO_START	0xf0
#define RFC5869_A1_INFO_LEN	10

#define RFC5869_A2_IKM_START	0x00
#define RFC5869_A2_IKM_LEN	80
#define RFC5869_A2_SALT_START	0x60
#define RFC5869_A2_SALT_LEN	80
#define RFC5869_A2_INFO_START	0xb0
#define RFC5869_A2_INFO_LEN	80

#define SEGMENT_TEST_INFO_LEN	40
#define SEGMENT_TEST_OKM_LEN	100

/* RFC 5869 A.1: ikm = 22 x 0x0b, salt = 0x00..0x0c, info = 0xf0..0xf9 */
static const u8 rfc5869_a1_okm[] = {
	0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a,
	0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f, 0x2a,
	0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c,
	0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4, 0xc5, 0xbf,
	0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18,
	0x58, 0x65
};

/* RFC 5869 A.2: ikm = 0x00..0x4f, salt = 0x60..0xaf, info = 0xb0..0xff */
static const u8 rfc5869_a2_okm[] = {
	0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1,
	0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49, 0x34,
	0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8,
	0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf, 0xa9, 0x7c,
	0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72,
	0x71, 0xcb, 0x41, 0xc6, 0x5e, 0x59, 0x0e, 0x09,
	0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8,
	0x36, 0x77, 0x93, 0xa9, 0xac, 0xa3, 0xdb, 0x71,
	0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87,
	0xc1, 0x4c, 0x01, 0xd5, 0xc1, 0xf3, 0x43, 0x4f,
	0x1d, 0x87
};

/* RFC 5869 A.3: ikm = 22 x 0x0b, zero-length salt and info */
static const u8 rfc5869_a3_okm[] = {
	0x8d, 0xa4, 0xe7, 0x75, 0xa5, 0x63, 0xc1, 0x8f,
	0x71, 0x5f, 0x80, 0x2a, 0x06, 0x3c, 0x5a, 0x31,
	0xb8, 0xa1, 0x1f, 0x5c, 0x5e, 0xe1, 0x87, 0x9e,
	0xc3, 0x45, 0x4e, 0x5f, 0x3c, 0x73, 0x8d, 0x2d,
	0x9d, 0x20, 0x13, 0x95, 0xfa, 0xa4, 0xb6, 0x1a,
	0x96, 0xc8
};

/* HKDF-SHA384 with the RFC 5869 A.1 inputs */
static const u8 hkdf_sha384_a1_okm[] = {
	0x9b, 0x50, 0x97, 0xa8, 0x60, 0x38, 0xb8, 0x05,
	0x30, 0x90, 0x76, 0xa4, 0x4b, 0x3a, 0x9f, 0x38,
	0x06, 0x3e, 0x25, 0xb5, 0x16, 0xdc, 0xbf, 0x36,
	0x9f, 0x39, 0x4c, 0xfa, 0xb4, 0x36, 0x85, 0xf7,
	0x48, 0xb6, 0x45, 0x77, 0x63, 0xe4, 0xf0, 0x20,
	0x4f, 0xc5
};

/* HKDF-SHA512 with the RFC 5869 A.1 inputs */
static const u8 hkdf_sha512_a1_okm[] = {
	0x83, 0x23, 0x90, 0x08, 0x6c, 0xda, 0x71, 0xfb,
	0x47, 0x62, 0x5b, 0xb5, 0xce, 0xb1, 0x68, 0xe4,
	0xc8, 0xe2, 0x6a, 0x1a, 0x16, 0xed, 0x34, 0xd9,
	0xfc, 0x7f, 0xe9, 0x2c, 0x14, 0x81, 0x57, 0x93,
	0x38, 0xda, 0x36, 0x2c, 0xb8, 0xd9, 0xf9, 0x25,
	0xd7, 0xcb
};

/*
 * HKDF-SHA512 with the RFC 5869 A.3 inputs and okm_len = 150, so that the
 * output spans multiple blocks and ends with a partial block
 */
static const u8 hkdf_sha512_a3_okm[] = {
	0xf5, 0xfa, 0x02, 0xb1, 0x82, 0x98, 0xa7, 0x2a,
	0x8c, 0x23, 0x89, 0x8a, 0x87, 0x03, 0x47, 0x2c,
	0x6e, 0xb1, 0x79, 0xdc, 0x20, 0x4c, 0x03, 0x42,
	0x5c, 0x97, 0x0e, 0x3b, 0x16, 0x4b, 0xf9, 0x0f,
	0xff, 0x22, 0xd0, 0x48, 0x36, 0xd0, 0xe2, 0x34,
	0x3b, 0xac, 0xc4, 0xe7, 0xcb, 0x60, 0x45, 0xfa,
	0xaa, 0x69, 0x8e, 0x0e, 0x3b, 0x3e, 0xb9, 0x13,
	0x31, 0x30, 0x6d, 0xef, 0x1d, 0xb8, 0x31, 0x9e,
	0x8a, 0x69, 0x9b, 0x5e, 0xe4, 0x5a, 0xb9, 0x93,
	0x84, 0x7d, 0xc4, 0xdf, 0x75, 0xbd, 0xe0, 0x23,
	0x69, 0x2c, 0x8c, 0x07, 0x10, 0xa6, 0x7a, 0x55,
	0x12, 0x3f, 0x10, 0xa8, 0xb2, 0xd8, 0x32, 0x7f,
	0x9e, 0xb1, 0x38, 0xda, 0x69, 0xd5, 0xbe, 0xa1,
	0xe0, 0x9a, 0x39, 0xea, 0x99, 0xa3, 0x41, 0xc0,
	0x0b, 0x2c, 0x9e, 0xe0, 0xd4, 0xba, 0x63, 0x21,
	0x15, 0xae, 0xc5, 0x16, 0xbb, 0x71, 0xe9, 0x22,
	0x7c, 0xb0, 0x0c, 0xa9, 0x8b, 0x7d, 0xfa, 0x8f,
	0x1c, 0x7e, 0xca, 0x60, 0xc9, 0x31, 0x28, 0x1f,
	0xa8, 0x5b, 0x87, 0x2f, 0x70, 0xb4
};

/*
 * Utility function to initialize ikm/salt/info buffers.
 * Fill 'buf' with 'len' consecutive byte values beginning with 'start'.
 */
static void fill_range(u8 *buf, size_t len, u8 start)
{
	for (size_t i = 0; i < len; i++)
		buf[i] = start + i;
}

static void test_hkdf_sha256_rfc5869(struct kunit *test)
{
	struct hmac_sha256_key prk;
	u8 ikm[RFC5869_A2_IKM_LEN];
	u8 salt[RFC5869_A2_SALT_LEN];
	u8 info[RFC5869_A2_INFO_LEN];
	u8 okm[sizeof(rfc5869_a2_okm)];
	struct hkdf_seg seg;

	/* A.1: basic test case */
	memset(ikm, RFC5869_A1_IKM_BYTE, RFC5869_A1_IKM_LEN);
	fill_range(salt, RFC5869_A1_SALT_LEN, RFC5869_A1_SALT_START);
	fill_range(info, RFC5869_A1_INFO_LEN, RFC5869_A1_INFO_START);
	hkdf_sha256_extract(&prk, salt, RFC5869_A1_SALT_LEN,
			    ikm, RFC5869_A1_IKM_LEN);
	seg = (struct hkdf_seg){ .data = info, .len = RFC5869_A1_INFO_LEN };
	hkdf_sha256_expand(&prk, &seg, 1, okm, sizeof(rfc5869_a1_okm));
	KUNIT_EXPECT_MEMEQ_MSG(test, okm, rfc5869_a1_okm,
			       sizeof(rfc5869_a1_okm), "RFC 5869 A.1");

	/* A.2: longer inputs, multi-block output ending in a partial block */
	fill_range(ikm, RFC5869_A2_IKM_LEN, RFC5869_A2_IKM_START);
	fill_range(salt, RFC5869_A2_SALT_LEN, RFC5869_A2_SALT_START);
	fill_range(info, RFC5869_A2_INFO_LEN, RFC5869_A2_INFO_START);
	hkdf_sha256_extract(&prk, salt, RFC5869_A2_SALT_LEN,
			    ikm, RFC5869_A2_IKM_LEN);
	seg = (struct hkdf_seg){ .data = info, .len = RFC5869_A2_INFO_LEN };
	hkdf_sha256_expand(&prk, &seg, 1, okm, sizeof(rfc5869_a2_okm));
	KUNIT_EXPECT_MEMEQ_MSG(test, okm, rfc5869_a2_okm,
			       sizeof(rfc5869_a2_okm), "RFC 5869 A.2");

	/* A.3: zero-length salt and info */
	memset(ikm, RFC5869_A1_IKM_BYTE, RFC5869_A1_IKM_LEN);
	hkdf_sha256_extract(&prk, NULL, 0, ikm, RFC5869_A1_IKM_LEN);
	hkdf_sha256_expand(&prk, NULL, 0, okm, sizeof(rfc5869_a3_okm));
	KUNIT_EXPECT_MEMEQ_MSG(test, okm, rfc5869_a3_okm,
			       sizeof(rfc5869_a3_okm),
			       "RFC 5869 A.3 with NULL salt and info");

	/* A.3 again, with a non-NULL empty salt and an empty info segment */
	hkdf_sha256_extract(&prk, salt, 0, ikm, RFC5869_A1_IKM_LEN);
	seg = (struct hkdf_seg){ .data = info, .len = 0 };
	hkdf_sha256_expand(&prk, &seg, 1, okm, sizeof(rfc5869_a3_okm));
	KUNIT_EXPECT_MEMEQ_MSG(test, okm, rfc5869_a3_okm,
			       sizeof(rfc5869_a3_okm),
			       "RFC 5869 A.3 with non-NULL empty salt and info");
}

static void test_hkdf_sha384_rfc5869_a1(struct kunit *test)
{
	struct hmac_sha384_key prk;
	u8 ikm[RFC5869_A1_IKM_LEN];
	u8 salt[RFC5869_A1_SALT_LEN];
	u8 info[RFC5869_A1_INFO_LEN];
	u8 okm[sizeof(hkdf_sha384_a1_okm)];
	struct hkdf_seg seg;

	memset(ikm, RFC5869_A1_IKM_BYTE, sizeof(ikm));
	fill_range(salt, sizeof(salt), RFC5869_A1_SALT_START);
	fill_range(info, sizeof(info), RFC5869_A1_INFO_START);
	seg = (struct hkdf_seg){ .data = info, .len = sizeof(info) };
	hkdf_sha384_extract(&prk, salt, sizeof(salt), ikm, sizeof(ikm));
	hkdf_sha384_expand(&prk, &seg, 1, okm, sizeof(okm));
	KUNIT_EXPECT_MEMEQ_MSG(test, okm, hkdf_sha384_a1_okm, sizeof(okm),
			       "SHA-384 with RFC 5869 A.1 inputs");
}

static void test_hkdf_sha512_rfc5869_a1_a3(struct kunit *test)
{
	struct hmac_sha512_key prk;
	u8 ikm[RFC5869_A1_IKM_LEN];
	u8 salt[RFC5869_A1_SALT_LEN];
	u8 info[RFC5869_A1_INFO_LEN];
	u8 okm[sizeof(hkdf_sha512_a3_okm)];
	struct hkdf_seg seg;

	memset(ikm, RFC5869_A1_IKM_BYTE, sizeof(ikm));
	fill_range(salt, sizeof(salt), RFC5869_A1_SALT_START);
	fill_range(info, sizeof(info), RFC5869_A1_INFO_START);
	seg = (struct hkdf_seg){ .data = info, .len = sizeof(info) };
	hkdf_sha512_extract(&prk, salt, sizeof(salt), ikm, sizeof(ikm));
	hkdf_sha512_expand(&prk, &seg, 1, okm, sizeof(hkdf_sha512_a1_okm));
	KUNIT_EXPECT_MEMEQ_MSG(test, okm, hkdf_sha512_a1_okm,
			       sizeof(hkdf_sha512_a1_okm),
			       "SHA-512 with RFC 5869 A.1 inputs");

	hkdf_sha512_extract(&prk, NULL, 0, ikm, sizeof(ikm));
	hkdf_sha512_expand(&prk, NULL, 0, okm, sizeof(hkdf_sha512_a3_okm));
	KUNIT_EXPECT_MEMEQ_MSG(test, okm, hkdf_sha512_a3_okm,
			       sizeof(hkdf_sha512_a3_okm),
			       "SHA-512 with RFC 5869 A.3 inputs and 150-byte OKM");
}

/* Test that splitting info into segments does not influence the output. */
static void test_hkdf_expand_info_segments(struct kunit *test)
{
	struct hmac_sha512_key prk;
	u8 ikm[RFC5869_A1_IKM_LEN];
	u8 info[SEGMENT_TEST_INFO_LEN];
	u8 okm_ref[SEGMENT_TEST_OKM_LEN];
	u8 okm[SEGMENT_TEST_OKM_LEN];
	struct hkdf_seg segs[sizeof(info)];

	memset(ikm, RFC5869_A1_IKM_BYTE, sizeof(ikm));
	fill_range(info, sizeof(info), 0x00);
	hkdf_sha512_extract(&prk, NULL, 0, ikm, sizeof(ikm));

	segs[0] = (struct hkdf_seg){ .data = info, .len = sizeof(info) };
	hkdf_sha512_expand(&prk, segs, 1, okm_ref, sizeof(okm_ref));

	/* every possible two-way split */
	for (size_t split = 0; split <= sizeof(info); split++) {
		segs[0] = (struct hkdf_seg){ .data = info, .len = split };
		segs[1] = (struct hkdf_seg){ .data = &info[split],
					     .len = sizeof(info) - split };
		memset(okm, 0, sizeof(okm));
		hkdf_sha512_expand(&prk, segs, 2, okm, sizeof(okm));
		KUNIT_EXPECT_MEMEQ_MSG(test, okm, okm_ref, sizeof(okm),
				       "failed for split=%zu", split);
	}

	/* one segment per byte */
	for (size_t i = 0; i < sizeof(info); i++)
		segs[i] = (struct hkdf_seg){ .data = &info[i], .len = 1 };
	memset(okm, 0, sizeof(okm));
	hkdf_sha512_expand(&prk, segs, sizeof(info), okm, sizeof(okm));
	KUNIT_EXPECT_MEMEQ_MSG(test, okm, okm_ref, sizeof(okm),
			       "one info segment per byte");
}

static struct kunit_case hkdf_test_cases[] = {
	KUNIT_CASE(test_hkdf_sha256_rfc5869),
	KUNIT_CASE(test_hkdf_sha384_rfc5869_a1),
	KUNIT_CASE(test_hkdf_sha512_rfc5869_a1_a3),
	KUNIT_CASE(test_hkdf_expand_info_segments),
	{},
};

static struct kunit_suite hkdf_test_suite = {
	.name = "hkdf",
	.test_cases = hkdf_test_cases,
};

kunit_test_suite(hkdf_test_suite);

MODULE_DESCRIPTION("KUnit tests for HKDF-SHA256, HKDF-SHA384, and HKDF-SHA512");
MODULE_LICENSE("GPL");
