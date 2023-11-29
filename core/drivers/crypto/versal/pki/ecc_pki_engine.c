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

	versal_ecc_get_key_size(curve, &bytes, &bits);

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
	uint32_t cq_status = io_read32((vaddr_t)versal_pki.cq);
	uint32_t cq_value = io_read32((vaddr_t)versal_pki.cq + 4);

	if ((cq_status != PKI_EXPECTED_CQ_STATUS) ||
		(cq_value != PKI_EXPECTED_CQ_VALUE))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_ecc_verify(uint32_t algo, struct ecc_public_key *key,
			 const uint8_t *msg, size_t msg_len,
			 const uint8_t *sig, size_t sig_len)
{
	TEE_Result ret = TEE_SUCCESS;

	size_t bits = 0;
	size_t bytes = 0;
	size_t len = 0;

	uintptr_t addr = (uintptr_t)versal_pki.rq_in;

	ret = versal_ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret)
		return ret;

	/* Copy public key */
	crypto_bignum_bn2bin_eswap(key->curve, key->x, (uint8_t *)addr);
	addr += bytes;
	crypto_bignum_bn2bin_eswap(key->curve, key->y, (uint8_t *)addr);
	addr += bytes;

	/* Copy signature */
	memcpy_swp((uint8_t *)addr, sig, sig_len / 2);
	addr += sig_len / 2;
	memcpy_swp((uint8_t *)addr, sig + sig_len / 2, sig_len / 2);
	addr += sig_len / 2;

	/* Copy hash */
	ret = versal_ecc_prepare_msg(algo, msg, msg_len, &len, (uint8_t *)addr);
	if (ret)
		return ret;
	if (len < bytes) {
		memset((uint8_t *)addr + len, 0, bytes - len);
	}
	addr += bytes;

	if (key->curve == TEE_ECC_CURVE_NIST_P521) {
		memset((uint8_t *)addr, 0, PKI_VERIFY_P521_PADD_BYTES);
		addr += PKI_VERIFY_P521_PADD_BYTES;
	}

	/* Build descriptors */
	ret = pki_build_descriptors(key->curve,
		PKI_DESC_OPTYPE_ECDSA_VERIFY, (uint32_t *)addr);
	if (ret)
		return ret;

	ret = pki_start_operation(PKI_NEW_REQUEST_MASK & (addr + 1));
	if (ret)
		return ret;

	ret = pki_check_status();
	if (ret)
		return ret;

	/* Clear memory */
	memset(versal_pki.rq_in, 0, PKI_QUEUE_BUF_SIZE);
	memset(versal_pki.cq, 0, PKI_QUEUE_BUF_SIZE);

	return TEE_SUCCESS;
}

TEE_Result versal_ecc_sign(uint32_t algo, struct ecc_keypair *key,
		       const uint8_t *msg, size_t msg_len,
		       uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t bits = 0;
	size_t bytes = 0;
	struct ecc_keypair ephemeral = { };

	ret = versal_ecc_get_key_size(key->curve, &bytes, &bits);
	if (ret)
		return ret;

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

	ret = versal_ecc_sign_ephemeral(algo, bytes, key, &ephemeral,
			   msg, msg_len, sig, sig_len);

	crypto_bignum_free(ephemeral.d);
	crypto_bignum_free(ephemeral.x);
	crypto_bignum_free(ephemeral.y);

	return ret;
}

TEE_Result versal_ecc_sign_ephemeral(uint32_t algo, size_t bytes,
			   struct ecc_keypair *key, struct ecc_keypair *ephemeral,
		       const uint8_t *msg, size_t msg_len,
		       uint8_t *sig, size_t *sig_len)
{
	TEE_Result ret = TEE_SUCCESS;
	size_t len = 0;

	uintptr_t addr = (uintptr_t)versal_pki.rq_in;

	/* Copy private key */
	crypto_bignum_bn2bin_eswap(key->curve, key->d, (uint8_t *)addr);
	addr += bytes;

	/* Copy ephemeral key */
	crypto_bignum_bn2bin_eswap(key->curve, ephemeral->d, (uint8_t *)addr);
	addr += bytes;

	/* Copy hash */
	ret = versal_ecc_prepare_msg(algo, msg, msg_len, &len, (uint8_t *)addr);
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

	return ret;
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

TEE_Result versal_ecc_hw_init(void)
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
