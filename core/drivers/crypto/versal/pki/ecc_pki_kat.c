// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) ProvenRun SAS 2023.
 */

#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <crypto/crypto_impl.h>
#include <initcall.h>
#include <ecc.h>
#include <kernel/panic.h>
#include <kernel/delay.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <string.h>
#include <tee/cache.h>
#include <tee/tee_cryp_utl.h>
#include <util.h>
#include <io.h>
#include <config.h>

static const uint8_t PubkeyQx_P256[] = {
	0xb7, 0xe0, 0x8a, 0xfd, 0xfe, 0x94, 0xba, 0xd3,
	0xf1, 0xdc, 0x8c, 0x73, 0x47, 0x98, 0xba, 0x1c,
	0x62, 0xb3, 0xa0, 0xad, 0x1e, 0x9e, 0xa2, 0xa3,
	0x82, 0x01, 0xcd, 0x08, 0x89, 0xbc, 0x7a, 0x19
};

static const uint8_t PubkeyQy_P256[] = {
	0x36, 0x03, 0xf7, 0x47, 0x95, 0x9d, 0xbf, 0x7a,
	0x4b, 0xb2, 0x26, 0xe4, 0x19, 0x28, 0x72, 0x90,
	0x63, 0xad, 0xc7, 0xae, 0x43, 0x52, 0x9e, 0x61,
	0xb5, 0x63, 0xbb, 0xc6, 0x06, 0xcc, 0x5e, 0x09,
};

static const uint8_t PubkeyQx_P384[] = {
	0x3b, 0xf7, 0x01, 0xbc, 0x9e, 0x9d, 0x36, 0xb4,
	0xd5, 0xf1, 0x45, 0x53, 0x43, 0xf0, 0x91, 0x26,
	0xf2, 0x56, 0x43, 0x90, 0xf2, 0xb4, 0x87, 0x36,
	0x50, 0x71, 0x24, 0x3c, 0x61, 0xe6, 0x47, 0x1f,
	0xb9, 0xd2, 0xab, 0x74, 0x65, 0x7b, 0x82, 0xf9,
	0x08, 0x64, 0x89, 0xd9, 0xef, 0x0f, 0x5c, 0xb5,
};

static const uint8_t PubkeyQy_P384[] = {
	0xd1, 0xa3, 0x58, 0xea, 0xfb, 0xf9, 0x52, 0xe6,
	0x8d, 0x53, 0x38, 0x55, 0xcc, 0xbd, 0xaa, 0x6f,
	0xf7, 0x5b, 0x13, 0x7a, 0x51, 0x01, 0x44, 0x31,
	0x99, 0x32, 0x55, 0x83, 0x55, 0x2a, 0x62, 0x95,
	0xff, 0xe5, 0x38, 0x2d, 0x00, 0xcf, 0xcd, 0xa3,
	0x03, 0x44, 0xa9, 0xb5, 0xb6, 0x8d, 0xb8, 0x55,
};

static const uint8_t PubkeyQx_P521[] = {
	0x00, 0x98, 0xe9, 0x1e, 0xef, 0x9a, 0x68, 0x45,
	0x28, 0x22, 0x30, 0x9c, 0x52, 0xfa, 0xb4, 0x53,
	0xf5, 0xf1, 0x17, 0xc1, 0xda, 0x8e, 0xd7, 0x96,
	0xb2, 0x55, 0xe9, 0xab, 0x8f, 0x64, 0x10, 0xcc,
	0xa1, 0x6e, 0x59, 0xdf, 0x40, 0x3a, 0x6b, 0xdc,
	0x6c, 0xa4, 0x67, 0xa3, 0x70, 0x56, 0xb1, 0xe5,
	0x4b, 0x30, 0x05, 0xd8, 0xac, 0x03, 0x0d, 0xec,
	0xfe, 0xb6, 0x8d, 0xf1, 0x8b, 0x17, 0x18, 0x85,
	0xd5, 0xc4,
};

static const uint8_t PubkeyQy_P521[] = {
	0x01, 0x64, 0x35, 0x0c, 0x32, 0x1a, 0xec, 0xfc,
	0x1c, 0xca, 0x1b, 0xa4, 0x36, 0x4c, 0x9b, 0x15,
	0x65, 0x61, 0x50, 0xb4, 0xb7, 0x8d, 0x6a, 0x48,
	0xd7, 0xd2, 0x8e, 0x7f, 0x31, 0x98, 0x5e, 0xf1,
	0x7b, 0xe8, 0x55, 0x43, 0x76, 0xb7, 0x29, 0x00,
	0x71, 0x2c, 0x4b, 0x83, 0xad, 0x66, 0x83, 0x27,
	0x23, 0x15, 0x26, 0xe3, 0x13, 0xf5, 0xf0, 0x92,
	0x99, 0x9a, 0x46, 0x32, 0xfd, 0x50, 0xd9, 0x46,
	0xbc, 0x2e,
};

/* Signature */
static const uint8_t SignR_P256[] = {
	0x2b, 0x42, 0xf5, 0x76, 0xd0, 0x7f, 0x41, 0x65,
	0xff, 0x65, 0xd1, 0xf3, 0xb1, 0x50, 0x0f, 0x81,
	0xe4, 0x4c, 0x31, 0x6f, 0x1f, 0x0b, 0x3e, 0xf5,
	0x73, 0x25, 0xb6, 0x9a, 0xca, 0x46, 0x10, 0x4f,
};

static const uint8_t SignS_P256[] = {
	0xdc, 0x42, 0xc2, 0x12, 0x2d, 0x63, 0x92, 0xcd,
	0x3e, 0x3a, 0x99, 0x3a, 0x89, 0x50, 0x2a, 0x81,
	0x98, 0xc1, 0x88, 0x6f, 0xe6, 0x9d, 0x26, 0x2c,
	0x4b, 0x32, 0x9b, 0xdb, 0x6b, 0x63, 0xfa, 0xf1,
};

static const uint8_t SignR_P384[] = {
	0x30, 0xea, 0x51, 0x4f, 0xc0, 0xd3, 0x8d, 0x82,
	0x08, 0x75, 0x6f, 0x06, 0x81, 0x13, 0xc7, 0xca,
	0xda, 0x9f, 0x66, 0xa3, 0xb4, 0x0e, 0xa3, 0xb3,
	0x13, 0xd0, 0x40, 0xd9, 0xb5, 0x7d, 0xd4, 0x1a,
	0x33, 0x27, 0x95, 0xd0, 0x2c, 0xc7, 0xd5, 0x07,
	0xfc, 0xef, 0x9f, 0xaf, 0x01, 0xa2, 0x70, 0x88,
};

static const uint8_t SignS_P384[] = {
	0xcc, 0x80, 0x8e, 0x50, 0x4b, 0xe4, 0x14, 0xf4,
	0x6c, 0x90, 0x27, 0xbc, 0xbf, 0x78, 0xad, 0xf0,
	0x67, 0xa4, 0x39, 0x22, 0xd6, 0xfc, 0xaa, 0x66,
	0xc4, 0x47, 0x68, 0x75, 0xfb, 0xb7, 0xb9, 0x4e,
	0xfd, 0x1f, 0x7d, 0x5d, 0xbe, 0x62, 0x0b, 0xfb,
	0x82, 0x1c, 0x46, 0xd5, 0x49, 0x68, 0x3a, 0xd8,
};

static const uint8_t SignR_P521[] = {
	0x01, 0x40, 0xc8, 0xed, 0xca, 0x57, 0x10, 0x8c,
	0xe3, 0xf7, 0xe7, 0xa2, 0x40, 0xdd, 0xd3, 0xad,
	0x74, 0xd8, 0x1e, 0x2d, 0xe6, 0x24, 0x51, 0xfc,
	0x1d, 0x55, 0x8f, 0xdc, 0x79, 0x26, 0x9a, 0xda,
	0xcd, 0x1c, 0x25, 0x26, 0xee, 0xee, 0xf3, 0x2f,
	0x8c, 0x04, 0x32, 0xa9, 0xd5, 0x6e, 0x2b, 0x4a,
	0x8a, 0x73, 0x28, 0x91, 0xc3, 0x7c, 0x9b, 0x96,
	0x64, 0x1a, 0x92, 0x54, 0xcc, 0xfe, 0x5d, 0xc3,
	0xe2, 0xba,
};

static const uint8_t SignS_P521[] = {
	0x00, 0xb2, 0x51, 0x88, 0x49, 0x2d, 0x58, 0xe8,
	0x08, 0xed, 0xeb, 0xd7, 0xbf, 0x44, 0x0e, 0xd2,
	0x0d, 0xb7, 0x71, 0xca, 0x7c, 0x61, 0x85, 0x95,
	0xd5, 0x39, 0x8e, 0x1b, 0x1c, 0x00, 0x98, 0xe3,
	0x00, 0xd8, 0xc8, 0x03, 0xec, 0x69, 0xec, 0x5f,
	0x46, 0xc8, 0x4f, 0xc6, 0x19, 0x67, 0xa3, 0x02,
	0xd3, 0x66, 0xc6, 0x27, 0xfc, 0xfa, 0x56, 0xf8,
	0x7f, 0x24, 0x1e, 0xf9, 0x21, 0xb6, 0xe6, 0x27,
	0xad, 0xbf,
};

static const uint8_t D_P256[] = {
	0xc4, 0x77, 0xf9, 0xf6, 0x5c, 0x22, 0xcc, 0xe2,
	0x06, 0x57, 0xfa, 0xa5, 0xb2, 0xd1, 0xd8, 0x12,
	0x23, 0x36, 0xf8, 0x51, 0xa5, 0x08, 0xa1, 0xed,
	0x04, 0xe4, 0x79, 0xc3, 0x49, 0x85, 0xbf, 0x96,
};

static const uint8_t D_P384[] = {
	0xf9, 0x2c, 0x02, 0xed, 0x62, 0x9e, 0x4b, 0x48,
	0xc0, 0x58, 0x4b, 0x1c, 0x6c, 0xe3, 0xa3, 0xe3,
	0xb4, 0xfa, 0xae, 0x4a, 0xfc, 0x6a, 0xcb, 0x04,
	0x55, 0xe7, 0x3d, 0xfc, 0x39, 0x2e, 0x6a, 0x0a,
	0xe3, 0x93, 0xa8, 0x56, 0x5e, 0x6b, 0x97, 0x14,
	0xd1, 0x22, 0x4b, 0x57, 0xd8, 0x3f, 0x8a, 0x08,
};

static const uint8_t D_P521[] = {
	0x01, 0x00, 0x08, 0x5f, 0x47, 0xb8, 0xe1, 0xb8,
	0xb1, 0x1b, 0x7e, 0xb3, 0x30, 0x28, 0xc0, 0xb2,
	0x88, 0x8e, 0x30, 0x4b, 0xfc, 0x98, 0x50, 0x19,
	0x55, 0xb4, 0x5b, 0xba, 0x14, 0x78, 0xdc, 0x18,
	0x4e, 0xee, 0xdf, 0x09, 0xb8, 0x6a, 0x5f, 0x7c,
	0x21, 0x99, 0x44, 0x06, 0x07, 0x27, 0x87, 0x20,
	0x5e, 0x69, 0xa6, 0x37, 0x09, 0xfe, 0x35, 0xaa,
	0x93, 0xba, 0x33, 0x35, 0x14, 0xb2, 0x4f, 0x96,
	0x17, 0x22,
};

static const uint8_t K_P256[] = {
	0x7a, 0x1a, 0x7e, 0x52, 0x79, 0x7f, 0xc8, 0xca,
	0xaa, 0x43, 0x5d, 0x2a, 0x4d, 0xac, 0xe3, 0x91,
	0x58, 0x50, 0x4b, 0xf2, 0x04, 0xfb, 0xe1, 0x9f,
	0x14, 0xdb, 0xb4, 0x27, 0xfa, 0xee, 0x50, 0xae,
};

static const uint8_t K_P384[] = {
	0x2e, 0x44, 0xef, 0x1f, 0x8c, 0x0b, 0xea, 0x83,
	0x94, 0xe3, 0xdd, 0xa8, 0x1e, 0xc6, 0xa7, 0x84,
	0x2a, 0x45, 0x9b, 0x53, 0x47, 0x01, 0x74, 0x9e,
	0x2e, 0xd9, 0x5f, 0x05, 0x4f, 0x01, 0x37, 0x68,
	0x08, 0x78, 0xe0, 0x74, 0x9f, 0xc4, 0x3f, 0x85,
	0xed, 0xca, 0xe0, 0x6c, 0xc2, 0xf4, 0x3f, 0xef,
};

static const uint8_t K_P521[] = {
	0x00, 0x00, 0xc9, 0x1e, 0x23, 0x49, 0xef, 0x6c,
	0xa2, 0x2d, 0x2d, 0xe3, 0x9d, 0xd5, 0x18, 0x19,
	0xb6, 0xaa, 0xd9, 0x22, 0xd3, 0xae, 0xcd, 0xea,
	0xb4, 0x52, 0xba, 0x17, 0x2f, 0x7d, 0x63, 0xe3,
	0x70, 0xce, 0xcd, 0x70, 0x57, 0x5f, 0x59, 0x7c,
	0x09, 0xa1, 0x74, 0xba, 0x76, 0xbe, 0xd0, 0x5a,
	0x48, 0xe5, 0x62, 0xbe, 0x06, 0x25, 0x33, 0x6d,
	0x16, 0xb8, 0x70, 0x31, 0x47, 0xa6, 0xa2, 0x31,
	0xd6, 0xbf,
};
static const uint8_t H_P256[] = {
	0xa4, 0x1a, 0x41, 0xa1, 0x2a, 0x79, 0x95, 0x48,
	0x21, 0x1c, 0x41, 0x0c, 0x65, 0xd8, 0x13, 0x3a,
	0xfd, 0xe3, 0x4d, 0x28, 0xbd, 0xd5, 0x42, 0xe4,
	0xb6, 0x80, 0xcf, 0x28, 0x99, 0xc8, 0xa8, 0xc4,
};

static const uint8_t H_P384[] = {
	0x5a, 0xea, 0x18, 0x7d, 0x1c, 0x4f, 0x6e, 0x1b,
	0x35, 0x05, 0x7d, 0x20, 0x12, 0x6d, 0x83, 0x6c,
	0x6a, 0xdb, 0xbc, 0x70, 0x49, 0xee, 0x02, 0x99,
	0xc9, 0x52, 0x9f, 0x5e, 0x0b, 0x3f, 0x8b, 0x5a,
	0x74, 0x11, 0x14, 0x9d, 0x6c, 0x30, 0xd6, 0xcb,
	0x2b, 0x8a, 0xf7, 0x0e, 0x0a, 0x78, 0x1e, 0x89,
};

static const uint8_t H_P521[] = {
	0x00, 0x00, 0xef, 0x88, 0xfb, 0x5a, 0xc0, 0x1f,
	0x35, 0xf5, 0xcb, 0x8a, 0x1b, 0x00, 0x8e, 0x80,
	0x11, 0x46, 0xc1, 0x39, 0x83, 0xcf, 0x8c, 0x2c,
	0xcf, 0x1d, 0x88, 0xaf, 0xa8, 0xe9, 0xfe, 0xde,
	0x12, 0x1c, 0x11, 0xfe, 0x82, 0x9d, 0x41, 0xb4,
	0x02, 0xb3, 0x2a, 0xdf, 0xde, 0x20, 0x67, 0x9c,
	0x3f, 0x4d, 0x91, 0x01, 0xa3, 0xc4, 0x07, 0x3a,
	0x2e, 0x49, 0x03, 0x9f, 0x5d, 0x38, 0x06, 0x1c,
	0xdb, 0xcc,
};

TEE_Result versal_ecc_kat(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
