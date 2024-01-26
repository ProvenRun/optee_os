// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) Foundries Ltd. 2022.
 * Author: Jorge Ramirez <jorge@foundries.io>
 */

#include <drvcrypt.h>
#include <drvcrypt_acipher.h>
#include <crypto/crypto_impl.h>
#include <initcall.h>
#include <ipi.h>
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

enum versal_ecc_err {
	KAT_KEY_NOTVALID_ERROR = 0xC0,
	KAT_FAILED_ERROR,
	NON_SUPPORTED_CURVE,
	KEY_ZERO,
	KEY_WRONG_ORDER,
	KEY_NOT_ON_CURVE,
	BAD_SIGN,
	GEN_SIGN_INCORRECT_HASH_LEN,
	VER_SIGN_INCORRECT_HASH_LEN,
	GEN_SIGN_BAD_RAND_NUM,
	GEN_KEY_ERR,
	INVALID_PARAM,
	VER_SIGN_R_ZERO,
	VER_SIGN_S_ZERO,
	VER_SIGN_R_ORDER_ERROR,
	VER_SIGN_S_ORDER_ERROR,
	KAT_INVLD_CRV_ERROR,
};

#define VERSAL_ECC_ERROR(m) { .error = (m), .name = TO_STR(m) }

static const char *versal_ecc_error(uint8_t err)
{
	struct {
		enum versal_ecc_err error;
		const char *name;
	} elist[] = {
		VERSAL_ECC_ERROR(KAT_KEY_NOTVALID_ERROR),
		VERSAL_ECC_ERROR(KAT_FAILED_ERROR),
		VERSAL_ECC_ERROR(NON_SUPPORTED_CURVE),
		VERSAL_ECC_ERROR(KEY_ZERO),
		VERSAL_ECC_ERROR(KEY_WRONG_ORDER),
		VERSAL_ECC_ERROR(KEY_NOT_ON_CURVE),
		VERSAL_ECC_ERROR(BAD_SIGN),
		VERSAL_ECC_ERROR(GEN_SIGN_INCORRECT_HASH_LEN),
		VERSAL_ECC_ERROR(VER_SIGN_INCORRECT_HASH_LEN),
		VERSAL_ECC_ERROR(GEN_SIGN_BAD_RAND_NUM),
		VERSAL_ECC_ERROR(GEN_KEY_ERR),
		VERSAL_ECC_ERROR(INVALID_PARAM),
		VERSAL_ECC_ERROR(VER_SIGN_R_ZERO),
		VERSAL_ECC_ERROR(VER_SIGN_S_ZERO),
		VERSAL_ECC_ERROR(VER_SIGN_R_ORDER_ERROR),
		VERSAL_ECC_ERROR(VER_SIGN_S_ORDER_ERROR),
		VERSAL_ECC_ERROR(KAT_INVLD_CRV_ERROR),
	};

	if (err <= KAT_INVLD_CRV_ERROR && err >= KAT_KEY_NOTVALID_ERROR) {
		if (elist[err - KAT_KEY_NOTVALID_ERROR].name)
			return elist[err - KAT_KEY_NOTVALID_ERROR].name;

		return "Invalid";
	}

	return "Unknown";
}

TEE_Result versal_ecc_verify(uint32_t algo, struct ecc_public_key *key,
			 const uint8_t *msg, size_t msg_len,
			 const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	uint8_t swp[TEE_SHA512_HASH_SIZE + 2] = { 0 };
	size_t len = 0;
	struct versal_ecc_verify_param *cmd = NULL;
	struct versal_cmd_args arg = { };
	struct versal_mbox_mem x = { };
	struct versal_mbox_mem s = { };
	struct versal_mbox_mem p = { };
	struct versal_mbox_mem cmd_buf = { };
	uint32_t err = 0;
	size_t bytes = 0;
	size_t bits = 0;

	if (sig_len % 2)
		return TEE_ERROR_SIGNATURE_INVALID;

	ret = versal_ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret)
		return ret;

	ret = versal_ecc_prepare_msg(algo, msg, msg_len, &len, (uint8_t *)&swp);
	if (ret)
		return ret;

	ret = versal_mbox_alloc(len, swp, &p);
	if (ret)
		return ret;

	ret = versal_mbox_alloc(bytes * 2, NULL, &x);
	if (ret)
		goto ou1;

	crypto_bignum_bn2bin_eswap(key->curve, key->x, x.buf);
	crypto_bignum_bn2bin_eswap(key->curve, key->y,
				   (uint8_t *)x.buf + bytes);
	/* Validate the public key for the curve */
	arg.data[0] = key->curve;
	arg.dlen = 1;
	arg.ibuf[0].mem = x;
	if (versal_crypto_request(VERSAL_ELLIPTIC_VALIDATE_PUBLIC_KEY,
				  &arg, &err)) {
		EMSG("Versal ECC: %s", versal_ecc_error(err));
		ret = TEE_ERROR_GENERIC;
		goto out2;
	}
	memset(&arg, 0, sizeof(arg));

	ret = versal_mbox_alloc(sig_len, NULL, &s);
	if (ret)
		goto out2;

	/* Swap the {R,S} components */
	memcpy_swp(s.buf, sig, sig_len / 2);
	memcpy_swp((uint8_t *)s.buf + sig_len / 2, sig + sig_len / 2,
		   sig_len / 2);

	ret = versal_mbox_alloc(sizeof(*cmd), NULL, &cmd_buf);
	if (ret)
		goto out3;

	cmd = cmd_buf.buf;
	cmd->signature_addr = virt_to_phys(s.buf);
	cmd->pub_key_addr = virt_to_phys(x.buf);
	cmd->hash_addr = virt_to_phys(p.buf);
	cmd->hash_len = p.len;
	cmd->curve = key->curve;

	arg.ibuf[0].mem = cmd_buf;
	arg.ibuf[1].mem = p;
	arg.ibuf[1].only_cache = true;
	arg.ibuf[2].mem = x;
	arg.ibuf[3].mem = s;

	if (versal_crypto_request(VERSAL_ELLIPTIC_VERIFY_SIGN, &arg, &err)) {
		EMSG("Versal ECC: %s", versal_ecc_error(err));
		ret = TEE_ERROR_GENERIC;
	}

	free(cmd);
out3:
	free(s.buf);
out2:
	free(x.buf);
out1:
	free(p.buf);

	return ret;
}

TEE_Result versal_ecc_sign(uint32_t algo, struct ecc_keypair *key,
		       const uint8_t *msg, size_t msg_len,
		       uint8_t *sig, size_t *sig_len)
{
	uint8_t swp[TEE_SHA512_HASH_SIZE + 2] = { 0 };
	size_t len = 0;
	struct versal_ecc_sign_param *cmd = NULL;
	struct versal_mbox_mem cmd_buf = { };
	struct ecc_keypair ephemeral = { };
	struct versal_cmd_args arg = { };
	struct versal_mbox_mem p = { };
	struct versal_mbox_mem k = { };
	struct versal_mbox_mem d = { };
	struct versal_mbox_mem s = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t err = 0;
	size_t bytes = 0;
	size_t bits = 0;

	ret = versal_ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret)
		return ret;

	/* Hash and update the length */
	ret = versal_ecc_prepare_msg(algo, msg, msg_len, &len, (uint8_t *)&swp);
	if (ret)
		return ret;
	ret = versal_mbox_alloc(len, swp, &p);
	if (ret)
		return ret;

	/* Ephemeral private key */
	ret = drvcrypt_asym_alloc_ecc_keypair(&ephemeral,
					      TEE_TYPE_ECDSA_KEYPAIR, bits);
	if (ret) {
		EMSG("Versal, can't allocate the ephemeral key");
		free(p.buf);
		return ret;
	}

	ephemeral.curve = key->curve;
	ret = crypto_acipher_gen_ecc_key(&ephemeral, bits);
	if (ret) {
		EMSG("Versal, can't generate the ephemeral key");
		free(p.buf);
		return ret;
	}

	ret = versal_mbox_alloc(bytes, NULL, &k);
	if (ret)
		goto out1;

	crypto_bignum_bn2bin_eswap(key->curve, ephemeral.d, k.buf);
	crypto_bignum_free(ephemeral.d);
	crypto_bignum_free(ephemeral.x);
	crypto_bignum_free(ephemeral.y);

	/* Private key*/
	ret = versal_mbox_alloc(bytes, NULL, &d);
	if (ret)
		goto out2;
	crypto_bignum_bn2bin_eswap(key->curve, key->d, d.buf);

	/* Signature */
	ret = versal_mbox_alloc(*sig_len, NULL, &s);
	if (ret)
		goto out3;

	/* IPI command */
	ret = versal_mbox_alloc(sizeof(*cmd), NULL, &cmd_buf);
	if (ret)
		goto out4;

	cmd = cmd_buf.buf;
	cmd->priv_key_addr = virt_to_phys(d.buf);
	cmd->epriv_key_addr = virt_to_phys(k.buf);
	cmd->hash_addr = virt_to_phys(p.buf);
	cmd->hash_len = p.len;
	cmd->curve = key->curve;

	arg.ibuf[0].mem = cmd_buf;
	arg.ibuf[1].mem = s;
	arg.ibuf[2].mem = k;
	arg.ibuf[3].mem = d;
	arg.ibuf[4].mem = p;

	if (versal_crypto_request(VERSAL_ELLIPTIC_GENERATE_SIGN, &arg, &err)) {
		EMSG("Versal ECC: %s", versal_ecc_error(err));
		ret = TEE_ERROR_GENERIC;
		goto error;
	}

	*sig_len = 2 * bytes;

	/* Swap the {R,S} components */
	memcpy_swp(sig, s.buf, *sig_len / 2);
	memcpy_swp(sig + *sig_len / 2, (uint8_t *)s.buf + *sig_len / 2,
		   *sig_len / 2);
error:
	free(cmd);
out4:
	free(s.buf);
out3:
	free(d.buf);
out2:
	free(k.buf);
out1:
	free(p.buf);

	return ret;
}

/* AMD/Xilinx Versal's Known Answer Tests */
#define XSECURE_ECDSA_KAT_NIST_P384	0
#define XSECURE_ECDSA_KAT_NIST_P521	2

TEE_Result versal_ecc_kat(void)
{
	struct versal_cmd_args arg = { };
	uint32_t err = 0;

	arg.data[arg.dlen++] = XSECURE_ECDSA_KAT_NIST_P384;
	if (versal_crypto_request(VERSAL_ELLIPTIC_KAT, &arg, &err)) {
		EMSG("Versal KAG NIST_P384: %s", versal_ecc_error(err));
		return TEE_ERROR_GENERIC;
	}

	/* Clean previous request */
	arg.dlen = 0;

	arg.data[arg.dlen++] = XSECURE_ECDSA_KAT_NIST_P521;
	if (versal_crypto_request(VERSAL_ELLIPTIC_KAT, &arg, &err)) {
		EMSG("Versal KAG NIST_P521 %s", versal_ecc_error(err));
		return TEE_ERROR_GENERIC;
	}

	return TEE_SUCCESS;
}

TEE_Result versal_ecc_gen_keypair(struct ecc_keypair *s __maybe_unused)
{
	/*
	 * Versal requires little endian so need to memcpy_swp on Versal IP ops.
	 * We chose not to do it here because some tests might be using
	 * their own keys
	 */

	return TEE_ERROR_NOT_SUPPORTED;
}

TEE_Result versal_ecc_hw_init(void)
{
	return TEE_SUCCESS;
}
