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

/* Software based ECDSA operations */
static const struct crypto_ecc_keypair_ops *pair_ops;
static const struct crypto_ecc_public_ops *pub_ops;

static TEE_Result ecc_get_key_size(uint32_t curve, size_t *bytes, size_t *bits)
{
	switch (curve) {
#if defined(PLATFORM_FLAVOR_adaptative)
	case TEE_ECC_CURVE_NIST_P256:
		*bits = 256;
		*bytes = 32;
		break;
#endif
	case TEE_ECC_CURVE_NIST_P384:
		*bits = 384;
		*bytes = 48;
		break;
	case TEE_ECC_CURVE_NIST_P521:
		*bits = 521;
		*bytes = 66;
		break;
	default:
		return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static void memcpy_swp(uint8_t *to, const uint8_t *from, size_t len)
{
	size_t i = 0;

	for (i = 0; i < len; i++)
		to[i] = from[len - 1 - i];
}

static void crypto_bignum_bn2bin_eswap(uint32_t curve,
				       struct bignum *from, uint8_t *to)
{
	uint8_t pad[66] = { 0 };
	size_t len = crypto_bignum_num_bytes(from);
	size_t bytes = 0;
	size_t bits = 0;

	if (ecc_get_key_size(curve, &bytes, &bits))
		panic();

	crypto_bignum_bn2bin(from, pad + bytes - len);
	memcpy_swp(to, pad, bytes);
}

static TEE_Result ecc_prepare_msg(uint32_t algo, const uint8_t *msg,
				  size_t msg_len, size_t *len, uint8_t *buf)
{
	if (msg_len > TEE_SHA512_HASH_SIZE + 2)
		return TEE_ERROR_BAD_PARAMETERS;

	if (algo == TEE_ALG_ECDSA_SHA384)
		*len = TEE_SHA384_HASH_SIZE;
	else if (algo == TEE_ALG_ECDSA_SHA512)
		*len = TEE_SHA512_HASH_SIZE + 2;
#if defined(PLATFORM_FLAVOR_adaptative)
	else if (algo == TEE_ALG_ECDSA_SHA256)
		*len = TEE_SHA256_HASH_SIZE;
#endif
	else
		return TEE_ERROR_NOT_SUPPORTED;

	/* Swap the hash/message and pad if necessary */
	memcpy_swp(buf, msg, msg_len);

	return TEE_SUCCESS;
}

#if defined(PLATFORM_FLAVOR_adaptative)

#define FPD_PKI_CRYPTO_BASEADDR			0x20400000000
#define FPD_PKI_CTRLSTAT_BASEADDR		0x20400050000

#define FPD_PKI_SIZE 					0x10000

#define PKI_ENGINE_CTRL_OFFSET			0x00000C00
#define PKI_ENGINE_CTRL_CM_MASK			0x1

#define PKI_CRYPTO_SOFT_RESET_OFFSET	0x00000038
#define PKI_CRYPTO_IRQ_STATUS_OFFSET	0x00000088
#define PKI_CRYPTO_IRQ_ENABLE_OFFSET	0x00000090
#define PKI_CRYPTO_IRQ_RESET_OFFSET		0x000000A0
#define PKI_RQ_CFG_PAGE_ADDR_IN_OFFSET	0x00000100
#define PKI_RQ_CFG_PAGE_ADDR_OUT_OFFSET	0x00000108
#define PKI_RQ_CFG_PAGE_SIZE_OFFSET		0x00000120
#define PKI_RQ_CFG_CQID_OFFSET			0x00000128
#define PKI_RQ_CFG_PERMISSIONS_OFFSET	0x00000130
#define PKI_RQ_CFG_QUEUE_DEPTH_OFFSET	0x00000140
#define PKI_CQ_CFG_ADDR_OFFSET			0x00001100
#define PKI_CQ_CFG_SIZE_OFFSET			0x00001108
#define PKI_CQ_CFG_IRQ_IDX_OFFSET		0x00001110
#define PKI_RQ_CTL_NEW_REQUEST_OFFSET	0x00002000
#define PKI_CQ_CTL_TRIGPOS_OFFSET		0x00002028

#define PKI_RQ_CFG_PERMISSIONS_SAFE		0x0
#define PKI_RQ_CFG_PAGE_SIZE_1024		0x10
#define PKI_RQ_CFG_CQID					0x0
#define	PKI_CQ_CFG_SIZE_4096			0xC
#define PKI_CQ_CFG_IRQ_ID_VAL			0x0
#define PKI_RQ_CFG_QUEUE_DEPTH_VAL		0x80
#define PKI_IRQ_ENABLE_VAL				0xFFFF
#define PKI_CQ_CTL_TRIGPOS_VAL			0x201

#define PKI_IRQ_DONE_STATUS_VAL			0x1

#define PKI_NEW_REQUEST_MASK			0x00000FFF

#define PKI_MAX_RETRY_COUNT				10000

#define PKI_QUEUE_BUF_SIZE				0x10000

struct versal_pki {
	vaddr_t regs;

	uint8_t *rq_in;
	uint8_t *rq_out;
	uint8_t *cq;
};

static struct versal_pki versal_pki;

/*
 * PKI Engine Descriptors
 */

#define PKI_DESC_LEN_BYTES					0x20

#define PKI_DESC_TAG_START					0x00000002
#define PKI_DESC_TAG_TFRI(sz)				((sz) << 16 | 0x0006)
#define PKI_DESC_TAG_TFRO(sz)				((sz) << 16 | 0x000E)
#define PKI_DESC_TAG_NTFY(id)				((id) << 16 | 0x0016)

#define PKI_DESC_OPTYPE_MOD_ADD				0x01
#define PKI_DESC_OPTYPE_ECC_POINTMUL		0x22
#define PKI_DESC_OPTYPE_ECDSA_SIGN			0x30
#define PKI_DESC_OPTYPE_ECDSA_VERIFY		0x31

#define PKI_DESC_ECC_FIELD_GFP				0x0

#define PKI_DESC_OPSIZE_P256				0x1F
#define PKI_DESC_OPSIZE_P384				0x2F
#define PKI_DESC_OPSIZE_P521				0x41

#define PKI_DESC_SELCURVE_P256				0x1
#define PKI_DESC_SELCURVE_P384				0x2
#define PKI_DESC_SELCURVE_P521				0x3

#define PKI_DESC_TAG_START_CMD(op, opsize, selcurve, field) \
	((op) | ((field) << 7) | ((opsize)  << 8) | ((selcurve) << 20))

#define PKI_SIGN_INPUT_OP_COUNT				3
#define PKI_VERIFY_INPUT_OP_COUNT			5

#define PKI_SIGN_OUTPUT_OP_COUNT			2
#define PKI_VERIFY_OUTPUT_OP_COUNT			0

#define PKI_SIGN_P521_PADD_BYTES			2
#define PKI_VERIFY_P521_PADD_BYTES			6

#define PKI_DEFAULT_REQID					0xB04EU

#define PKI_EXPECTED_CQ_STATUS				0
#define PKI_EXPECTED_CQ_VALUE				(PKI_DEFAULT_REQID << 16 | 0x1)

#define PKI_RESET_DELAY_US		10

static void pki_get_opsize(uint32_t curve, uint32_t op, size_t *in_sz, size_t *out_sz)
{
	size_t bits;
	size_t bytes;

	ecc_get_key_size(curve, &bytes, &bits);

	switch (op) {
		case PKI_DESC_OPTYPE_ECDSA_SIGN:
			*in_sz = bytes * PKI_SIGN_INPUT_OP_COUNT;
			*out_sz = bytes * PKI_SIGN_OUTPUT_OP_COUNT;
			break;
		case PKI_DESC_OPTYPE_ECDSA_VERIFY:
			*in_sz = bytes * PKI_VERIFY_INPUT_OP_COUNT;
			*out_sz = bytes * PKI_VERIFY_OUTPUT_OP_COUNT;
			break;
		default:
			break;
	}
}

static TEE_Result pki_build_descriptors(uint32_t curve, uint32_t op, uint32_t *descs)
{
	size_t in_sz = 0;
	size_t out_sz = 0;

	pki_get_opsize(curve, op, &in_sz, &out_sz);

	descs[0] = PKI_DESC_TAG_START;

	switch (curve) {
		case TEE_ECC_CURVE_NIST_P256:
			descs[1] = PKI_DESC_TAG_START_CMD(
				op, PKI_DESC_OPSIZE_P256, PKI_DESC_SELCURVE_P256,
				PKI_DESC_ECC_FIELD_GFP);
			break;

		case TEE_ECC_CURVE_NIST_P384:
			descs[1] = PKI_DESC_TAG_START_CMD(
				op, PKI_DESC_OPSIZE_P384, PKI_DESC_SELCURVE_P384,
				PKI_DESC_ECC_FIELD_GFP);
			break;

		case TEE_ECC_CURVE_NIST_P521:
			descs[1] = PKI_DESC_TAG_START_CMD(
				op, PKI_DESC_OPSIZE_P521, PKI_DESC_SELCURVE_P521,
				PKI_DESC_ECC_FIELD_GFP);
			break;

		default:
			return TEE_ERROR_NOT_SUPPORTED;
	}

	descs[2] = PKI_DESC_TAG_TFRI(in_sz);
	descs[3] = 0;
	descs[4] = PKI_DESC_TAG_TFRO(out_sz);
	descs[5] = 0x10000;
	descs[6] = PKI_DESC_TAG_NTFY(PKI_DEFAULT_REQID);
	descs[7] = 0;

	return TEE_SUCCESS;
}

static TEE_Result pki_start_operation(uint32_t reqval)
{
	TEE_Result ret = TEE_ERROR_TIMEOUT;

	uint32_t retries = PKI_MAX_RETRY_COUNT;

	/* Soft reset */
	io_write32(versal_pki.regs + PKI_CRYPTO_SOFT_RESET_OFFSET, 1);
	udelay(PKI_RESET_DELAY_US);
	io_write32(versal_pki.regs + PKI_CRYPTO_SOFT_RESET_OFFSET, 0);

	cache_operation(TEE_CACHEFLUSH, versal_pki.rq_in, PKI_QUEUE_BUF_SIZE);

	io_write32(versal_pki.regs + PKI_RQ_CFG_PERMISSIONS_OFFSET,
		PKI_RQ_CFG_PERMISSIONS_SAFE);
	io_write64(versal_pki.regs + PKI_RQ_CFG_PAGE_ADDR_IN_OFFSET,
		virt_to_phys(versal_pki.rq_in));
	io_write64(versal_pki.regs + PKI_RQ_CFG_PAGE_ADDR_OUT_OFFSET,
		virt_to_phys(versal_pki.rq_out));
	io_write64(versal_pki.regs + PKI_CQ_CFG_ADDR_OFFSET,
		virt_to_phys(versal_pki.cq));
	io_write32(versal_pki.regs + PKI_RQ_CFG_PAGE_SIZE_OFFSET,
		PKI_RQ_CFG_PAGE_SIZE_1024);
	io_write32(versal_pki.regs + PKI_RQ_CFG_CQID_OFFSET, PKI_RQ_CFG_CQID);
	io_write32(versal_pki.regs + PKI_CQ_CFG_SIZE_OFFSET,
		PKI_CQ_CFG_SIZE_4096);
	io_write32(versal_pki.regs + PKI_CQ_CFG_IRQ_IDX_OFFSET,
		PKI_CQ_CFG_IRQ_ID_VAL);
	io_write32(versal_pki.regs + PKI_RQ_CFG_QUEUE_DEPTH_OFFSET,
		PKI_RQ_CFG_QUEUE_DEPTH_VAL);
	io_write64(versal_pki.regs + PKI_CRYPTO_IRQ_ENABLE_OFFSET,
		PKI_IRQ_ENABLE_VAL);

	io_write32(versal_pki.regs + PKI_CQ_CTL_TRIGPOS_OFFSET,
		PKI_CQ_CTL_TRIGPOS_VAL);
	io_write64(versal_pki.regs + PKI_RQ_CTL_NEW_REQUEST_OFFSET, reqval);

	/* Wait for completion */
	while (retries--) {
		uint64_t irq_status =
			io_read64(versal_pki.regs + PKI_CRYPTO_IRQ_STATUS_OFFSET);
		if (irq_status == PKI_IRQ_DONE_STATUS_VAL) {
			io_write64(versal_pki.regs + PKI_CRYPTO_IRQ_RESET_OFFSET,
				PKI_IRQ_DONE_STATUS_VAL);
			ret = TEE_SUCCESS;
			break;
		}
	}

	cache_operation(TEE_CACHEINVALIDATE, versal_pki.cq, PKI_QUEUE_BUF_SIZE);
	cache_operation(TEE_CACHEINVALIDATE, versal_pki.rq_out, PKI_QUEUE_BUF_SIZE);

	return ret;
}

static TEE_Result pki_check_status(void)
{
	uint32_t *cq_status = (uint32_t *)versal_pki.cq;

	if ((cq_status[0] != PKI_EXPECTED_CQ_STATUS) ||
		(cq_status[1] != PKI_EXPECTED_CQ_VALUE))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

static TEE_Result verify(uint32_t algo, struct ecc_public_key *key,
			 const uint8_t *msg, size_t msg_len,
			 const uint8_t *sig, size_t sig_len)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

static TEE_Result sign(uint32_t algo, struct ecc_keypair *key,
		       const uint8_t *msg, size_t msg_len,
		       uint8_t *sig, size_t *sig_len)
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t ret = 0;
	size_t bits = 0;
	size_t bytes = 0;
	size_t len = 0;
	struct ecc_keypair ephemeral = { };

	uintptr_t addr = (uintptr_t)versal_pki.rq_in;

	ret = ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret != TEE_SUCCESS) {
		if (ret != TEE_ERROR_NOT_SUPPORTED)
			return ret;

		/* Fallback to software */
		return pair_ops->sign(algo, key, msg, msg_len, sig, sig_len);
	}

	/* Copy private key */
	crypto_bignum_bn2bin_eswap(key->curve, key->d, (uint8_t *)addr);
	addr += bytes;

	/* Ephemeral private key */
	ret = drvcrypt_asym_alloc_ecc_keypair(&ephemeral,
					      TEE_TYPE_ECDSA_KEYPAIR, bits);
	if (ret) {
		EMSG("Versal, can't allocate the ephemeral key");
		return ret;
	}

	ephemeral.curve = key->curve;
	ret = crypto_acipher_gen_ecc_key(&ephemeral, bits);
	if (ret) {
		EMSG("Versal, can't generate the ephemeral key");
		return ret;
	}

	crypto_bignum_bn2bin_eswap(key->curve, ephemeral.d, (uint8_t *)addr);
	addr += bytes;

	crypto_bignum_free(ephemeral.d);
	crypto_bignum_free(ephemeral.x);
	crypto_bignum_free(ephemeral.y);

	/* Copy hash */
	ret = ecc_prepare_msg(algo, msg, msg_len, &len, (uint8_t *)addr);
	if (ret)
		return ret;
	if (len < bytes) {
		memset((uint8_t *)addr + len, 0, bytes - len);
	}
	addr += bytes;

	if (key->curve == TEE_ECC_CURVE_NIST_P521) {
		memset((uint8_t *)addr, 0, PKI_SIGN_P521_PADD_BYTES);
		addr += PKI_SIGN_P521_PADD_BYTES;
	}

	/* Build descriptors */
	ret = pki_build_descriptors(key->curve,
		PKI_DESC_OPTYPE_ECDSA_SIGN, (uint32_t *)addr);
	if (ret)
		return ret;

	ret = pki_start_operation(PKI_NEW_REQUEST_MASK & (addr + 1));
	if (ret)
		return ret;

	ret = pki_check_status();
	if (ret)
		return ret;

	/* Copy signature back */
	*sig_len = 2 * bytes;

	memcpy_swp(sig, versal_pki.rq_out, bytes);
	memcpy_swp(sig + bytes, versal_pki.rq_out + bytes, bytes);

	/* Clear memory */
	memset(versal_pki.rq_in, 0, PKI_QUEUE_BUF_SIZE);
	memset(versal_pki.rq_out, 0, PKI_QUEUE_BUF_SIZE);
	memset(versal_pki.cq, 0, PKI_QUEUE_BUF_SIZE);

	return res;
}

static TEE_Result ecc_kat(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

#define PSX_CRF_RST_PKI			0xEC200340

#define PKI_ASSERT_RESET		1

static TEE_Result versal_pki_engine_reset(void)
{
	vaddr_t reset;

	/* Reset the PKI engine */
	reset = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
			      PSX_CRF_RST_PKI, SMALL_PAGE_SIZE);
	if (!reset)
		return TEE_ERROR_GENERIC;

	io_write32(reset, PKI_ASSERT_RESET);
	udelay(PKI_RESET_DELAY_US);
	io_write32(reset, PKI_ASSERT_RESET);

	core_mmu_remove_mapping(MEM_AREA_IO_SEC,
					  (void *)reset, SMALL_PAGE_SIZE);

	return TEE_SUCCESS;
}

#define FPD_SLCR_BASEADDR		0xEC8C0000
#define FPD_SLCR_SIZE			0x4000

#define FPD_SLCR_WPROT0_OFFSET			0x00000000
#define FPD_SLCR_PKI_MUX_SEL_OFFSET		0x00002000

#define FPD_CLEAR_WRITE_PROTECT 		0

#define PKI_MUX_SEL_MASK				0x00000001
#define PKI_MUX_SELECT					0x00000001

static TEE_Result versal_pki_engine_slcr_config(void)
{
	vaddr_t fpd_slcr;

	fpd_slcr = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
					  FPD_SLCR_BASEADDR, FPD_SLCR_SIZE);
	if (!fpd_slcr)
		return TEE_ERROR_GENERIC;

	/* Clear FPD SCLR write protect reg */
	io_write32(fpd_slcr + FPD_SLCR_WPROT0_OFFSET,
					  FPD_CLEAR_WRITE_PROTECT);

	/* PKI mux selection */
	io_mask32(fpd_slcr + FPD_SLCR_PKI_MUX_SEL_OFFSET,
				  PKI_MUX_SELECT, PKI_MUX_SEL_MASK);

	core_mmu_remove_mapping(MEM_AREA_IO_SEC,
					  (void *)fpd_slcr, FPD_SLCR_SIZE);

	return TEE_SUCCESS;
}

static TEE_Result versal_pki_config_cm(void)
{
	vaddr_t regs;
	uint64_t val;

	regs = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
						  FPD_PKI_CTRLSTAT_BASEADDR, FPD_PKI_SIZE);
	if (!regs)
		return TEE_ERROR_GENERIC;

	val = io_read64(regs + PKI_ENGINE_CTRL_OFFSET);
	if (IS_ENABLED(CFG_VERSAL_PKI_COUNTER_MEASURES)) {
		val &= ~PKI_ENGINE_CTRL_CM_MASK;
	} else {
		val |= PKI_ENGINE_CTRL_CM_MASK;
	}
	io_write64(regs + PKI_ENGINE_CTRL_OFFSET, val);

	core_mmu_remove_mapping(MEM_AREA_IO_SEC,
						  (void *)regs, FPD_PKI_SIZE);

	return TEE_SUCCESS;
}

static TEE_Result ecc_hw_init(void)
{
	TEE_Result ret;

	ret = versal_pki_engine_slcr_config();
	if (ret != TEE_SUCCESS)
		return ret;

	ret = versal_pki_engine_reset();
	if (ret != TEE_SUCCESS)
		return ret;

	ret = versal_pki_config_cm();
	if (ret != TEE_SUCCESS)
		return ret;

	versal_pki.regs = (vaddr_t)core_mmu_add_mapping(MEM_AREA_IO_SEC,
		FPD_PKI_CRYPTO_BASEADDR, FPD_PKI_SIZE);
	if (!versal_pki.regs)
		return TEE_ERROR_GENERIC;

	/* Allocate queues */
	versal_pki.rq_in = memalign(CACHELINE_LEN, PKI_QUEUE_BUF_SIZE);
	if (!versal_pki.rq_in)
		return TEE_ERROR_GENERIC;

	versal_pki.rq_out = memalign(CACHELINE_LEN, PKI_QUEUE_BUF_SIZE);
	if (!versal_pki.rq_out)
		return TEE_ERROR_GENERIC;

	versal_pki.cq = memalign(CACHELINE_LEN, PKI_QUEUE_BUF_SIZE);
	if (!versal_pki.cq)
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
#else
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

static TEE_Result verify(uint32_t algo, struct ecc_public_key *key,
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

	ret = ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret != TEE_SUCCESS) {
		if (ret != TEE_ERROR_NOT_SUPPORTED)
			return ret;

		/* Fallback to software */
		return pub_ops->verify(algo, key, msg, msg_len, sig, sig_len);
	}

	ret = ecc_prepare_msg(algo, msg, msg_len, &len, &swp);
	if (ret)
		return ret;
	versal_mbox_alloc(len, swp, &p);

	versal_mbox_alloc(bytes * 2, NULL, &x);
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
		goto out;
	}
	memset(&arg, 0, sizeof(arg));

	versal_mbox_alloc(sig_len, NULL, &s);
	/* Swap the {R,S} components */
	memcpy_swp(s.buf, sig, sig_len / 2);
	memcpy_swp((uint8_t *)s.buf + sig_len / 2, sig + sig_len / 2,
		   sig_len / 2);
	versal_mbox_alloc(sizeof(*cmd), NULL, &cmd_buf);

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
out:
	free(p.buf);
	free(x.buf);
	free(s.buf);
	free(cmd);

	return ret;
}

static TEE_Result sign(uint32_t algo, struct ecc_keypair *key,
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

	ret = ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret != TEE_SUCCESS) {
		if (ret != TEE_ERROR_NOT_SUPPORTED)
			return ret;

		/* Fallback to software */
		return pair_ops->sign(algo, key, msg, msg_len, sig, sig_len);
	}

	/* Hash and update the length */
	ret = ecc_prepare_msg(algo, msg, msg_len, &len, &swp);
	if (ret)
		return ret;
	versal_mbox_alloc(len, swp, &p);

	/* Ephemeral private key */
	ret = drvcrypt_asym_alloc_ecc_keypair(&ephemeral,
					      TEE_TYPE_ECDSA_KEYPAIR, bits);
	if (ret) {
		EMSG("Versal, can't allocate the ephemeral key");
		return ret;
	}

	ephemeral.curve = key->curve;
	ret = crypto_acipher_gen_ecc_key(&ephemeral, bits);
	if (ret) {
		EMSG("Versal, can't generate the ephemeral key");
		return ret;
	}

	versal_mbox_alloc(bytes, NULL, &k);
	crypto_bignum_bn2bin_eswap(key->curve, ephemeral.d, k.buf);
	crypto_bignum_free(ephemeral.d);
	crypto_bignum_free(ephemeral.x);
	crypto_bignum_free(ephemeral.y);

	/* Private key*/
	versal_mbox_alloc(bytes, NULL, &d);
	crypto_bignum_bn2bin_eswap(key->curve, key->d, d.buf);

	/* Signature */
	versal_mbox_alloc(*sig_len, NULL, &s);

	/* IPI command */
	versal_mbox_alloc(sizeof(*cmd), NULL, &cmd_buf);

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
		goto out;
	}

	*sig_len = 2 * bytes;

	/* Swap the {R,S} components */
	memcpy_swp(sig, s.buf, *sig_len / 2);
	memcpy_swp(sig + *sig_len / 2, (uint8_t *)s.buf + *sig_len / 2,
		   *sig_len / 2);
out:
	free(cmd);
	free(k.buf);
	free(p.buf);
	free(s.buf);
	free(d.buf);

	return ret;
}

/* AMD/Xilinx Versal's Known Answer Tests */
#define XSECURE_ECDSA_KAT_NIST_P384	0
#define XSECURE_ECDSA_KAT_NIST_P521	2

static TEE_Result ecc_kat(void)
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

static TEE_Result ecc_hw_init(void)
{
	return TEE_SUCCESS;
}
#endif

static TEE_Result shared_secret(struct ecc_keypair *private_key,
				struct ecc_public_key *public_key,
				void *secret, size_t *secret_len)
{
	return pair_ops->shared_secret(private_key, public_key,
					  secret, secret_len);
}

static TEE_Result do_shared_secret(struct drvcrypt_secret_data *sdata)
{
	return shared_secret(sdata->key_priv,
			     sdata->key_pub,
			     sdata->secret.data,
			     &sdata->secret.length);
}

static TEE_Result do_sign(struct drvcrypt_sign_data *sdata)
{
	return sign(sdata->algo,
		    sdata->key,
		    sdata->message.data,
		    sdata->message.length,
		    sdata->signature.data,
		    &sdata->signature.length);
}

static TEE_Result do_verify(struct drvcrypt_sign_data *sdata)
{
	return verify(sdata->algo,
		      sdata->key,
		      sdata->message.data,
		      sdata->message.length,
		      sdata->signature.data,
		      sdata->signature.length);
}

static TEE_Result do_gen_keypair(struct ecc_keypair *s, size_t size_bits)
{
	/*
	 * Versal requires little endian so need to memcpy_swp on Versal IP ops.
	 * We chose not to do it here because some tests might be using
	 * their own keys
	 */
	return pair_ops->generate(s, size_bits);
}

static TEE_Result do_alloc_keypair(struct ecc_keypair *s,
				   uint32_t type, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	/* This driver only supports ECDH/ECDSA */
	if (type != TEE_TYPE_ECDSA_KEYPAIR &&
	    type != TEE_TYPE_ECDH_KEYPAIR)
		return TEE_ERROR_NOT_IMPLEMENTED;

	ret = crypto_asym_alloc_ecc_keypair(s, TEE_TYPE_ECDSA_KEYPAIR,
					    size_bits);
	if (ret)
		return TEE_ERROR_NOT_IMPLEMENTED;

	/*
	 * Ignore the software operations, the crypto API will populate
	 * this interface.
	 */
	s->ops = NULL;

	return TEE_SUCCESS;
}

static TEE_Result do_alloc_publickey(struct ecc_public_key *s,
				     uint32_t type, size_t size_bits)
{
	TEE_Result ret = TEE_SUCCESS;

	/* This driver only supports ECDH/ECDSA */
	if (type != TEE_TYPE_ECDSA_PUBLIC_KEY &&
	    type != TEE_TYPE_ECDH_PUBLIC_KEY)
		return TEE_ERROR_NOT_IMPLEMENTED;

	ret = crypto_asym_alloc_ecc_public_key(s, TEE_TYPE_ECDSA_PUBLIC_KEY,
					       size_bits);
	if (ret)
		return TEE_ERROR_NOT_IMPLEMENTED;

	/*
	 * Ignore the software operations, the crypto API will populate
	 * this interface.
	 */
	s->ops = NULL;

	return TEE_SUCCESS;
}

static void do_free_publickey(struct ecc_public_key *s)
{
	return pub_ops->free(s);
}

static struct drvcrypt_ecc driver_ecc = {
	.shared_secret = do_shared_secret,
	.alloc_publickey = do_alloc_publickey,
	.free_publickey = do_free_publickey,
	.alloc_keypair = do_alloc_keypair,
	.gen_keypair = do_gen_keypair,
	.verify = do_verify,
	.sign = do_sign,
};

static TEE_Result ecc_init(void)
{
	TEE_Result ret;

	/* HW initialization if needed */
	ret = ecc_hw_init();
	if (ret != TEE_SUCCESS)
		return ret;

	/* Run KAT self-tests */
	ret = ecc_kat();
	if (ret != TEE_SUCCESS)
		return ret;

	/* Fall back to software implementations if needed */
	pair_ops = crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDSA_KEYPAIR);
	if (!pair_ops)
		return TEE_ERROR_GENERIC;

	pub_ops = crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDSA_PUBLIC_KEY);
	if (!pub_ops)
		return TEE_ERROR_GENERIC;

	/* This driver supports both ECDH and ECDSA */
	assert((pub_ops ==
		crypto_asym_get_ecc_public_ops(TEE_TYPE_ECDH_PUBLIC_KEY)) &&
	       (pair_ops ==
		crypto_asym_get_ecc_keypair_ops(TEE_TYPE_ECDH_KEYPAIR)));

	return drvcrypt_register_ecc(&driver_ecc);
}

driver_init(ecc_init);
