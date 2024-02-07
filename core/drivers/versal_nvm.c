// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (C) 2022 Foundries.io Ltd
 * Jorge Ramirez-Ortiz <jorge@foundries.io>
 */

#include <arm.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_mbox.h>
#include <initcall.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <mm/core_memprot.h>
#include <string.h>
#include <tee/cache.h>
#include <io.h>

#include "drivers/versal_nvm.h"

#define NVM_WORD_LEN 4

/* Protocol API with the remote processor */
#define NVM_MODULE_SHIFT		8
#define NVM_MODULE			11
#define NVM_API_ID(_id) ((NVM_MODULE << NVM_MODULE_SHIFT) | (_id))

#define __aligned_efuse			__aligned(CACHELINE_LEN)

/* Internal */
struct versal_efuse_puf_fuse_addr {
	uint64_t data_addr;
	uint32_t start_row;
	uint32_t num_rows;
	uint8_t env_monitor_dis;
	uint8_t prgm_puf_fuse;
	uint8_t pad[46];
};

/*
 * Max size of the buffer needed for the remote processor to DMA efuse _data_
 * to/from
 */
#define EFUSE_MAX_LEN (EFUSE_MAX_USER_FUSES * sizeof(uint32_t))

#if defined(PLATFORM_FLAVOR_adaptative)
enum versal_nvm_api_id {
	API_FEATURES						= 0,
	BBRAM_WRITE_AES_KEY					= 1,
	BBRAM_ZEROIZE						= 2,
	BBRAM_WRITE_USER_DATA				= 3,
	BBRAM_READ_USER_DATA				= 4,
	BBRAM_LOCK_WRITE_USER_DATA			= 5,
	BBRAM_WRITE_AES_KEY_FROM_PLOAD		= 6,
	EFUSE_WRITE_AES_KEY 				= 7,
	EFUSE_WRITE_AES_KEY_FROM_PLOAD		= 8,
	EFUSE_WRITE_PPK_HASH				= 9,
	EFUSE_WRITE_PPK_HASH_FROM_PLOAD		= 10,
	EFUSE_WRITE_IV						= 11,
	EFUSE_WRITE_IV_FROM_PLOAD			= 12,
	EFUSE_WRITE_GLITCH_CONFIG			= 13,
	EFUSE_WRITE_DEC_ONLY				= 14,
	EFUSE_WRITE_REVOCATION_ID			= 15,
	EFUSE_WRITE_OFFCHIP_REVOKE_ID		= 16,
	EFUSE_WRITE_MISC_CTRL_BITS			= 17,
	EFUSE_WRITE_SEC_CTRL_BITS			= 18,
	EFUSE_WRITE_MISC1_CTRL_BITS			= 19,
	EFUSE_WRITE_BOOT_ENV_CTRL_BITS		= 20,
	EFUSE_WRITE_FIPS_INFO				= 21,
	EFUSE_WRITE_UDS_FROM_PLOAD			= 22,
	EFUSE_WRITE_DME_KEY_FROM_PLOAD		= 23,
	EFUSE_WRITE_DME_REVOKE				= 24,
	EFUSE_WRITE_PLM_UPDATE				= 25,
	EFUSE_WRITE_BOOT_MODE_DISABLE		= 26,
	EFUSE_WRITE_CRC						= 27,
	EFUSE_WRITE_DME_MODE				= 28,
	EFUSE_WRITE_PUF_HD_FROM_PLOAD		= 29,
	EFUSE_WRITE_PUF						= 30,
	EFUSE_WRITE_ROM_RSVD				= 31,
	EFUSE_WRITE_PUF_CTRL_BITS			= 32,
	EFUSE_READ_CACHE					= 33,
	EFUSE_RELOAD_N_PRGM_PROT_BITS		= 34,
	EFUSE_INVALID						= 35,
};
#else
enum versal_nvm_api_id {
	API_FEATURES				= 0,
	BBRAM_WRITE_AES_KEY			= 1,
	BBRAM_ZEROIZE				= 2,
	BBRAM_WRITE_USER_DATA			= 3,
	BBRAM_READ_USER_DATA			= 4,
	BBRAM_LOCK_WRITE_USER_DATA		= 5,
	EFUSE_WRITE				= 6,
	EFUSE_WRITE_PUF				= 7,
	EFUSE_PUF_USER_FUSE_WRITE		= 8,
	EFUSE_READ_IV				= 9,
	EFUSE_READ_REVOCATION_ID		= 10,
	EFUSE_READ_OFFCHIP_REVOCATION_ID	= 11,
	EFUSE_READ_USER_FUSES			= 12,
	EFUSE_READ_MISC_CTRL			= 13,
	EFUSE_READ_SEC_CTRL			= 14,
	EFUSE_READ_SEC_MISC1			= 15,
	EFUSE_READ_BOOT_ENV_CTRL		= 16,
	EFUSE_READ_PUF_SEC_CTRL			= 17,
	EFUSE_READ_PPK_HASH			= 18,
	EFUSE_READ_DEC_EFUSE_ONLY		= 19,
	EFUSE_READ_DNA				= 20,
	EFUSE_READ_PUF_USER_FUSES		= 21,
	EFUSE_READ_PUF				= 22,
	EFUSE_INVALID				= 23,
};
#endif

/* uint64_t are memory addresses */
struct versal_efuse_data {
	uint64_t env_mon_dis_flag;
	uint64_t aes_key_addr;
	uint64_t ppk_hash_addr;
	uint64_t dec_only_addr;
	uint64_t sec_ctrl_addr;
	uint64_t misc_ctrl_addr;
	uint64_t revoke_id_addr;
	uint64_t iv_addr;
	uint64_t user_fuse_addr;
	uint64_t glitch_cfg_addr;
	uint64_t boot_env_ctrl_addr;
	uint64_t misc1_ctrl_addr;
	uint64_t offchip_id_addr;
	uint8_t pad[24];
};

/* Helper read and write requests (not part of the protocol) */
struct versal_nvm_buf {
	size_t len;
	void *buf;
};

struct versal_nvm_read_req {
	enum versal_nvm_api_id efuse_id;
	enum versal_nvm_revocation_id revocation_id;
	enum versal_nvm_offchip_id offchip_id;
	enum versal_nvm_ppk_type ppk_type;
	enum versal_nvm_iv_type iv_type;
	struct versal_nvm_buf ibuf[VERSAL_MAX_IPI_BUF];
};

struct versal_bbram_data {
	size_t aes_key_len;
	uint32_t user_data;
};

struct versal_nvm_write_req {
	struct versal_efuse_data data;
	struct versal_bbram_data bbram;
	struct versal_nvm_buf ibuf[VERSAL_MAX_IPI_BUF];
	enum versal_nvm_api_id efuse_id;
};

static TEE_Result
prepare_cmd(struct versal_ipi_cmd *cmd, enum versal_nvm_api_id efuse,
	    struct versal_nvm_buf *ibufs, uint32_t *arg)
{
	uint32_t a = 0;
	uint32_t b = 0;
	size_t i = 0;

	cmd->data[i++] = NVM_API_ID(efuse);
	if (arg)
		cmd->data[i++] = *arg;

	if (!ibufs[0].buf)
		return TEE_SUCCESS;

	reg_pair_from_64(virt_to_phys(ibufs[0].buf), &b, &a);

	cmd->data[i++] = a;
	cmd->data[i++] = b;

	for (i = 0; i < VERSAL_MAX_IPI_BUF; i++) {
		cmd->ibuf[i].mem.alloc_len = ibufs[i].len;
		cmd->ibuf[i].mem.buf = ibufs[i].buf;
	}

	return TEE_SUCCESS;
}

static TEE_Result efuse_req(enum versal_nvm_api_id efuse,
			    struct versal_nvm_buf *ibufs, uint32_t *arg)
{
	struct versal_ipi_cmd cmd = { };
	TEE_Result ret = TEE_SUCCESS;

	ret = prepare_cmd(&cmd, efuse, ibufs, arg);
	if (ret)
		return ret;

	ret = versal_mbox_notify_pmc(&cmd, NULL, NULL);
	if (ret)
		EMSG("Mailbox error");

	return ret;
}

static TEE_Result versal_alloc_read_buffer(struct versal_nvm_read_req *req)
{
	assert(req);
	req->ibuf[0].len = 1024;
	req->ibuf[0].buf = alloc_cache_aligned(req->ibuf[0].len);
	if (!req->ibuf[0].buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	return TEE_SUCCESS;
}

static void versal_free_read_buffer(struct versal_nvm_read_req *req)
{
	assert(req);
	free(req->ibuf[0].buf);
}

static void *versal_get_read_buffer(struct versal_nvm_read_req *req)
{
	assert(req);
	return req->ibuf[0].buf;
}

#if defined(PLATFORM_FLAVOR_adaptative)
static TEE_Result versal_nvm_read(struct versal_nvm_read_req *req)
{
	if (!req)
		return TEE_ERROR_GENERIC;

	switch (req->efuse_id) {
	case EFUSE_READ_CACHE:
	case BBRAM_READ_USER_DATA:
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, NULL);
}

static TEE_Result versal_nvm_write(struct versal_nvm_write_req *req)
{
	uint32_t *arg = NULL;
	uint32_t val = 0;

	switch (req->efuse_id) {
	case BBRAM_WRITE_AES_KEY:
		val = req->bbram.aes_key_len;
		arg = &val;
		break;
	case BBRAM_WRITE_USER_DATA:
		val = req->bbram.user_data;
		arg = &val;
		break;
	case BBRAM_ZEROIZE:
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, arg);
}
#else
static TEE_Result versal_nvm_read(struct versal_nvm_read_req *req)
{
	uint32_t *arg = NULL;
	uint32_t val = 0;

	if (!req)
		return TEE_ERROR_GENERIC;

	switch (req->efuse_id) {
	case EFUSE_READ_DNA:
	case EFUSE_READ_DEC_EFUSE_ONLY:
	case EFUSE_READ_PUF_SEC_CTRL:
	case EFUSE_READ_BOOT_ENV_CTRL:
	case EFUSE_READ_SEC_CTRL:
	case EFUSE_READ_MISC_CTRL:
	case EFUSE_READ_SEC_MISC1:
	case EFUSE_READ_USER_FUSES:
	case EFUSE_READ_PUF_USER_FUSES:
	case EFUSE_READ_PUF:
		break;
	case EFUSE_READ_OFFCHIP_REVOCATION_ID:
		val = req->offchip_id;
		arg = &val;
		break;
	case EFUSE_READ_REVOCATION_ID:
		val = req->revocation_id;
		arg = &val;
		break;
	case EFUSE_READ_IV:
		val = req->iv_type;
		arg = &val;
		break;
	case EFUSE_READ_PPK_HASH:
		val = req->ppk_type;
		arg = &val;
		break;
	case BBRAM_READ_USER_DATA:
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, arg);
}

static TEE_Result versal_nvm_write(struct versal_nvm_write_req *req)
{
	uint32_t *arg = NULL;
	uint32_t val = 0;

	switch (req->efuse_id) {
	case BBRAM_WRITE_AES_KEY:
		val = req->bbram.aes_key_len;
		arg = &val;
		break;
	case BBRAM_WRITE_USER_DATA:
		val = req->bbram.user_data;
		arg = &val;
		break;
	case BBRAM_ZEROIZE:
	case EFUSE_PUF_USER_FUSE_WRITE:
	case EFUSE_WRITE_PUF:
	case EFUSE_WRITE:
		break;
	default:
		return TEE_ERROR_GENERIC;
	}

	return efuse_req(req->efuse_id, req->ibuf, arg);
}
#endif

TEE_Result versal_bbram_write_aes_key(uint8_t *key, size_t len)
{
	struct versal_nvm_write_req req __aligned_efuse = {
		.efuse_id = BBRAM_WRITE_AES_KEY,
		.bbram.aes_key_len = len,
	};
	void *buf = NULL;

	if (len != 32)
		return TEE_ERROR_BAD_PARAMETERS;

	buf = alloc_cache_aligned(1024);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(buf, key, len);

	req.ibuf[0].buf = buf;
	req.ibuf[0].len = 1024;

	if (versal_nvm_write(&req)) {
		free(buf);
		return TEE_ERROR_GENERIC;
	}
	free(buf);

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_zeroize(void)
{
	struct versal_nvm_write_req req __aligned_efuse  = {
		.efuse_id = BBRAM_ZEROIZE,
	};

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_write_user_data(uint32_t data)
{
	struct versal_nvm_write_req req __aligned_efuse = {
		.efuse_id = BBRAM_WRITE_USER_DATA,
		.bbram.user_data = data,
	};

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_read_user_data(uint32_t *data)
{
	struct versal_nvm_read_req req = {
		.efuse_id = BBRAM_READ_USER_DATA,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(data, versal_get_read_buffer(&req), sizeof(*data));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_bbram_lock_write_user_data(void)
{
	struct versal_nvm_write_req req __aligned_efuse  = {
		.efuse_id = BBRAM_LOCK_WRITE_USER_DATA,
	};

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

#if defined(PLATFORM_FLAVOR_adaptative)
static TEE_Result versal_efuse_read_cache(uint16_t off, uint16_t num,
				   uint32_t *buf, size_t len)
{
	struct versal_ipi_cmd cmd = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t a = 0;
	uint32_t b = 0;

	if (buf == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (len < num * NVM_WORD_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_mbox_alloc(num * NVM_WORD_LEN, NULL, &p);
	if (ret)
		return ret;

	reg_pair_from_64(virt_to_phys(p.buf), &b, &a);

	cmd.data[0] = NVM_API_ID(EFUSE_READ_CACHE);
	cmd.data[1] = (num << 16) | off;
	cmd.data[2] = a;
	cmd.data[3] = b;

	cmd.ibuf[0].mem = p;

	ret = versal_mbox_notify_pmc(&cmd, NULL, NULL);
	if (ret) {
		EMSG("Mailbox error");
	} else {
		memcpy(buf, p.buf, num * NVM_WORD_LEN);
	}

	versal_mbox_free(&p);
	return ret;
}

#define EFUSE_CACHE_DNA_OFFSET			 				0x20
#define EFUSE_CACHE_BOOT_ENV_CTRL_OFFSET				0x94
#define EFUSE_CACHE_MISC_CTRL_OFFSET					0xA0
#define EFUSE_CACHE_PUF_ECC_CTRL_OFFSET					0xA4
#define EFUSE_CACHE_PUF_CHASH_OFFSET					0xA8
#define EFUSE_CACHE_SEC_CTRL_OFFSET						0xAC
#define EFUSE_CACHE_REVOCATION_ID0_OFFSET				0xB0
#define EFUSE_CACHE_SEC_MISC0_OFFSET					0xE4
#define EFUSE_CACHE_SEC_MISC1_OFFSET					0xE8
#define EFUSE_CACHE_PPK0_OFFSET							0x100
#define EFUSE_CACHE_PPK1_OFFSET							0x120
#define EFUSE_CACHE_PPK2_OFFSET							0x140
#define EFUSE_CACHE_OFFCHIP_REVOKE_ID0_OFFSET			0x160
#define EFUSE_CACHE_METAHEADER_IV_RANGE0_OFFSET			0x180
#define EFUSE_CACHE_BLACK_IV0_OFFSET					0x1D0
#define EFUSE_CACHE_PLM_IV_RANGE0_OFFSET				0x1DC
#define EFUSE_CACHE_DATA_PARTITION_IV_RANGE0_OFFSET		0x1E8
#define EFUSE_CACHE_USER0_OFFSET						0x240
#define EFUSE_CACHE_PUF_SYN0_OFFSET						0x300

TEE_Result versal_efuse_read_dna(uint32_t *buf, size_t len)
{
	if (len < EFUSE_DNA_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	return versal_efuse_read_cache(EFUSE_CACHE_DNA_OFFSET,
					   EFUSE_DNA_LEN / NVM_WORD_LEN, buf, len);
}

TEE_Result versal_efuse_read_user_data(uint32_t *buf, size_t len,
				       uint32_t first, size_t num)
{
	uint16_t offset;

	if (first + num > EFUSE_MAX_USER_FUSES || len < num * NVM_WORD_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	offset = EFUSE_CACHE_USER0_OFFSET + first * NVM_WORD_LEN;

	return versal_efuse_read_cache(offset, num, buf, len);
}

TEE_Result versal_efuse_read_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type)
{
	uint16_t offset;

	switch (type) {
	case EFUSE_META_HEADER_IV_RANGE:
		offset = EFUSE_CACHE_METAHEADER_IV_RANGE0_OFFSET;
		break;
	case EFUSE_BLACK_IV:
		offset = EFUSE_CACHE_BLACK_IV0_OFFSET;
		break;
	case EFUSE_PLM_IV_RANGE:
		offset = EFUSE_CACHE_PLM_IV_RANGE0_OFFSET;
		break;
	case EFUSE_DATA_PARTITION_IV_RANGE:
		offset = EFUSE_CACHE_DATA_PARTITION_IV_RANGE0_OFFSET;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return versal_efuse_read_cache(offset, EFUSE_IV_LEN / NVM_WORD_LEN, buf, len);
}

TEE_Result versal_efuse_read_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type)
{
	uint16_t offset;

	switch (type) {
	case EFUSE_PPK0:
		offset = EFUSE_CACHE_PPK0_OFFSET;
		break;
	case EFUSE_PPK1:
		offset = EFUSE_CACHE_PPK1_OFFSET;
		break;
	case EFUSE_PPK2:
		offset = EFUSE_CACHE_PPK2_OFFSET;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return versal_efuse_read_cache(offset, EFUSE_PPK_LEN / NVM_WORD_LEN, buf, len);
}

TEE_Result versal_efuse_read_revoke_id(uint32_t *buf, size_t len,
				       enum versal_nvm_revocation_id id)
{
	return versal_efuse_read_cache(
				   EFUSE_CACHE_REVOCATION_ID0_OFFSET + id * NVM_WORD_LEN,
				   EFUSE_REVOCATION_ID_LEN / NVM_WORD_LEN, buf, len);
}

TEE_Result versal_efuse_read_misc_ctrl(struct versal_efuse_misc_ctrl_bits *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t misc_ctrl = 0;

	if (buf == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_MISC_CTRL_OFFSET, 1,
				   &misc_ctrl, sizeof(uint32_t));
	if (ret)
		return ret;

	buf->glitch_det_halt_boot_en = ((misc_ctrl & GENMASK_32(31,30)) >> 30);
	buf->glitch_det_rom_monitor_en = ((misc_ctrl & BIT(29)) >> 29);
	buf->halt_boot_error = ((misc_ctrl & GENMASK_32(22, 21)) >> 21);
	buf->halt_boot_env = ((misc_ctrl & GENMASK_32(20, 19)) >> 19);
	buf->crypto_kat_en = ((misc_ctrl & BIT(15)) >> 15);
	buf->lbist_en = ((misc_ctrl & BIT(14)) >> 14);
	buf->safety_mission_en = ((misc_ctrl & BIT(8)) >> 8);
	buf->ppk0_invalid = ((misc_ctrl & GENMASK_32(7, 6)) >> 6);
	buf->ppk1_invalid = ((misc_ctrl & GENMASK_32(5, 4)) >> 4);
	buf->ppk2_invalid = ((misc_ctrl & GENMASK_32(3, 2)) >> 2);

	return ret;
}

TEE_Result versal_efuse_read_sec_ctrl(struct versal_efuse_sec_ctrl_bits *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t sec_ctrl = 0;

	if (buf == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_CTRL_OFFSET, 1,
				   &sec_ctrl, sizeof(uint32_t));
	if (ret)
		return ret;

	buf->aes_dis = (sec_ctrl & BIT(0));
	buf->jtag_err_out_dis = ((sec_ctrl & BIT(1)) >> 1);
	buf->jtag_dis = ((sec_ctrl & BIT(2)) >> 2);
	buf->ppk0_wr_lk = ((sec_ctrl & BIT(6)) >> 6);
	buf->ppk1_wr_lk = ((sec_ctrl & BIT(7)) >> 7);
	buf->ppk2_wr_lk = ((sec_ctrl & BIT(8)) >> 8);
	buf->aes_crc_lk = ((sec_ctrl & GENMASK_32(10, 9)) >> 9);
	buf->aes_wr_lk = ((sec_ctrl & BIT(11)) >> 11);
	buf->user_key0_crc_lk = ((sec_ctrl & BIT(12)) >> 12);
	buf->user_key0_wr_lk = ((sec_ctrl & BIT(13)) >> 13);
	buf->user_key1_crc_lk = ((sec_ctrl & BIT(14)) >> 14);
	buf->user_key1_wr_lk = ((sec_ctrl & BIT(15)) >> 15);
	buf->sec_dbg_dis = ((sec_ctrl & GENMASK_32(20, 19)) >> 19);
	buf->sec_lock_dbg_dis = ((sec_ctrl & GENMASK_32(22, 21)) >> 21);
	buf->boot_env_wr_lk = ((sec_ctrl & BIT(28)) >> 28);
	buf->reg_init_dis = ((sec_ctrl & GENMASK_32(31, 30)) >> 30);

	return ret;
}

TEE_Result versal_efuse_read_sec_misc1(struct versal_efuse_sec_misc1_bits *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t sec_misc1 = 0;

	if (buf == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_MISC1_OFFSET, 1,
				   &sec_misc1, sizeof(uint32_t));
	if (ret)
		return ret;

	buf->lpd_mbist_en = ((sec_misc1 & GENMASK_32(12, 10)) >> 10);
	buf->pmc_mbist_en = ((sec_misc1 & GENMASK_32(9, 7)) >> 7);
	buf->lpd_noc_sc_en = ((sec_misc1 & GENMASK_32(6, 4)) >> 4);
	buf->sysmon_volt_mon_en = ((sec_misc1 & GENMASK_32(3, 2)) >> 2);
	buf->sysmon_temp_mon_en = (sec_misc1 & GENMASK_32(1, 0));

	return ret;
}

TEE_Result versal_efuse_read_boot_env_ctrl(
				    struct versal_efuse_boot_env_ctrl_bits *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t boot_env_ctrl = 0;

	if (buf == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_BOOT_ENV_CTRL_OFFSET, 1,
				   &boot_env_ctrl, sizeof(uint32_t));
	if (ret)
		return ret;

	buf->sysmon_temp_en = ((boot_env_ctrl & BIT(21)) >> 21);
	buf->sysmon_volt_en = ((boot_env_ctrl & BIT(20)) >> 20);
	buf->sysmon_temp_hot = ((boot_env_ctrl & GENMASK_32(18, 17)) >> 17);
	buf->sysmon_volt_pmc = ((boot_env_ctrl & GENMASK_32(13, 12)) >> 12);
	buf->sysmon_volt_pslp = ((boot_env_ctrl & GENMASK_32(11, 10)) >> 10);
	buf->sysmon_volt_soc = ((boot_env_ctrl & GENMASK_32(9, 8)) >> 8);
	buf->sysmon_temp_cold = (boot_env_ctrl & GENMASK_32(1, 0));

	return ret;
}

TEE_Result versal_efuse_read_offchip_revoke_id(uint32_t *buf, size_t len,
					       enum versal_nvm_offchip_id id)
{
	if (id == EFUSE_INVLD)
		return TEE_ERROR_BAD_PARAMETERS;

	return versal_efuse_read_cache(
				   EFUSE_CACHE_OFFCHIP_REVOKE_ID0_OFFSET + id * NVM_WORD_LEN,
				   EFUSE_REVOCATION_ID_LEN / NVM_WORD_LEN, buf, len);
}

TEE_Result versal_efuse_read_dec_only(uint32_t *buf, size_t len)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t sec_misc0 = 0;

	if (len < EFUSE_DEC_ONLY_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_MISC0_OFFSET, 1,
				   &sec_misc0, sizeof(uint32_t));
	if (ret)
		return ret;

	sec_misc0 &= GENMASK_32(15, 0);

	memcpy(buf, &sec_misc0, EFUSE_DEC_ONLY_LEN);

	return ret;
}

TEE_Result versal_efuse_read_puf_sec_ctrl(struct versal_efuse_puf_sec_ctrl_bits
					  *buf)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t puf_ctrl = 0;
	uint32_t sec_ctrl = 0;

	if (buf == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_cache(EFUSE_CACHE_PUF_ECC_CTRL_OFFSET, 1,
				   &puf_ctrl, sizeof(uint32_t));
	if (ret)
		return ret;

	/*
	 * Some fuses have moved from PUF_ECC_CTRL to SECURITY_CTRL
	 */
	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_CTRL_OFFSET, 1,
				   &sec_ctrl, sizeof(uint32_t));
	if (ret)
		return ret;

	buf->puf_regen_dis = ((puf_ctrl & BIT(31)) >> 31);
	buf->puf_hd_invalid = ((puf_ctrl & BIT(30)) >> 30);
	buf->puf_test2_dis = ((puf_ctrl & BIT(29)) >> 29);
	buf->puf_dis = ((sec_ctrl & BIT(18)) >> 18);
	buf->puf_syn_lk = ((sec_ctrl & BIT(16)) >> 16);

	return ret;
}

TEE_Result versal_efuse_read_puf(struct versal_efuse_puf_header *buf)
{
	TEE_Result ret = TEE_SUCCESS;

	if (buf == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	ret = versal_efuse_read_puf_sec_ctrl(&buf->sec_ctrl);
	if (ret)
		return ret;

	ret = versal_efuse_read_cache(EFUSE_CACHE_SEC_CTRL_OFFSET, 1,
				   &buf->aux, sizeof(uint32_t));
	if (ret)
		return ret;

	buf->aux &= GENMASK_32(23, 0);

	ret = versal_efuse_read_cache(EFUSE_CACHE_PUF_CHASH_OFFSET, 1,
				   &buf->chash, sizeof(uint32_t));
	if (ret)
		return ret;

	ret = versal_efuse_read_cache(EFUSE_CACHE_PUF_SYN0_OFFSET,
				   PUF_SYN_DATA_WORDS, buf->efuse_syn_data,
				   PUF_SYN_DATA_WORDS * NVM_WORD_LEN);
	return ret;
}

TEE_Result versal_efuse_read_puf_as_user_fuse(
				   struct versal_efuse_puf_user_fuse *p __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result versal_efuse_write_user_data(uint32_t *buf __unused,
				    size_t len __unused, uint32_t first __unused,
					size_t num __unused)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

#define EFUSE_ENV_DIS_FLAG		0

#define EFUSE_AES_KEY_ID		0
#define EFUSE_USER_KEY0_ID		1
#define EFUSE_USER_KEY1_ID		2

static TEE_Result do_write_efuses_buffer(enum versal_nvm_api_id id,
			   uint16_t type, uint32_t *buf, size_t len)
{
	struct versal_ipi_cmd cmd = { };
	struct versal_mbox_mem p = { };
	TEE_Result ret = TEE_SUCCESS;
	uint32_t a = 0;
	uint32_t b = 0;

	ret = versal_mbox_alloc(len, buf, &p);
	if (ret)
		return ret;

	reg_pair_from_64(virt_to_phys(p.buf), &b, &a);

	cmd.data[0] = NVM_API_ID(id);
	cmd.data[1] = (type << 16) | EFUSE_ENV_DIS_FLAG;
	cmd.data[2] = a;
	cmd.data[3] = b;

	cmd.ibuf[0].mem = p;

	ret = versal_mbox_notify_pmc(&cmd, NULL, NULL);

	versal_mbox_free(&p);
	return ret;
}

static TEE_Result do_write_efuses_value(enum versal_nvm_api_id id, uint32_t val)
{
	struct versal_ipi_cmd cmd = { };
	TEE_Result ret = TEE_SUCCESS;

	cmd.data[0] = NVM_API_ID(id);
	cmd.data[1] = EFUSE_ENV_DIS_FLAG;
	cmd.data[2] = val;

	ret = versal_mbox_notify_pmc(&cmd, NULL, NULL);

	return ret;
}


TEE_Result versal_efuse_write_aes_keys(struct versal_efuse_aes_keys *keys)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_Result res;

	if (keys == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (keys->prgm_aes_key) {
		res = do_write_efuses_buffer(EFUSE_WRITE_AES_KEY, EFUSE_AES_KEY_ID,
					   keys->aes_key, EFUSE_AES_KEY_LEN);
		if (res) {
			DMSG("Error programming AES key (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	if (keys->prgm_user_key0) {
		res = do_write_efuses_buffer(EFUSE_WRITE_AES_KEY, EFUSE_USER_KEY0_ID,
					   keys->user_key0, EFUSE_AES_KEY_LEN);
		if (res) {
			DMSG("Error programming User key 0 (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	if (keys->prgm_user_key1) {
		res = do_write_efuses_buffer(EFUSE_WRITE_AES_KEY, EFUSE_USER_KEY1_ID,
					   keys->user_key1, EFUSE_AES_KEY_LEN);
		if (res) {
			DMSG("Error programming User key 1 (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	return ret;
}

TEE_Result versal_efuse_write_ppk_hash(struct versal_efuse_ppk_hash *hash)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_Result res;

	if (hash == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (hash->prgm_ppk0_hash) {
		res = do_write_efuses_buffer(EFUSE_WRITE_PPK_HASH, EFUSE_PPK0,
					   hash->ppk0_hash, EFUSE_PPK_LEN);
		if (res) {
			DMSG("Error programming PPK hash 0 (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	if (hash->prgm_ppk1_hash) {
		res = do_write_efuses_buffer(EFUSE_WRITE_PPK_HASH, EFUSE_PPK1,
					   hash->ppk1_hash, EFUSE_PPK_LEN);
		if (res) {
			DMSG("Error programming PPK hash 1 (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	if (hash->prgm_ppk2_hash) {
		res = do_write_efuses_buffer(EFUSE_WRITE_PPK_HASH, EFUSE_PPK2,
					   hash->ppk2_hash, EFUSE_PPK_LEN);
		if (res) {
			DMSG("Error programming PPK hash 2 (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	return ret;
}

TEE_Result versal_efuse_write_iv(struct versal_efuse_ivs *p)
{
	TEE_Result ret = TEE_SUCCESS;
	TEE_Result res;

	if (p == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	if (p->prgm_meta_header_iv) {
		res = do_write_efuses_buffer(EFUSE_WRITE_IV, EFUSE_META_HEADER_IV_RANGE,
					   p->meta_header_iv, EFUSE_IV_LEN);
		if (res) {
			DMSG("Error programming meta header IV (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	if (p->prgm_blk_obfus_iv) {
		res = do_write_efuses_buffer(EFUSE_WRITE_IV, EFUSE_BLACK_IV,
					   p->blk_obfus_iv, EFUSE_IV_LEN);
		if (res) {
			DMSG("Error programming black IV (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	if (p->prgm_plm_iv) {
		res = do_write_efuses_buffer(EFUSE_WRITE_IV, EFUSE_PLM_IV_RANGE,
					   p->plm_iv, EFUSE_IV_LEN);
		if (res) {
			DMSG("Error programming plm IV (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	if (p->prgm_data_partition_iv) {
		res = do_write_efuses_buffer(EFUSE_WRITE_IV, EFUSE_DATA_PARTITION_IV_RANGE,
					   p->data_partition_iv, EFUSE_IV_LEN);
		if (res) {
			DMSG("Error programming data partition IV (ret = 0x%" PRIx32 ")", res);
			ret = TEE_ERROR_GENERIC;
		}
	}

	return ret;
}

TEE_Result versal_efuse_write_dec_only(struct versal_efuse_dec_only *p)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result versal_efuse_write_sec(struct versal_efuse_sec_ctrl_bits *p)
{
	uint32_t val = 0;

	if (p == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	val = ((p->reg_init_dis & 0x3) << 30) |
		  ((p->boot_env_wr_lk & 0x1) << 28) |
		  ((p->sec_lock_dbg_dis & 0x3) << 21) |
		  ((p->sec_dbg_dis & 0x3) << 19) |
		  ((p->user_key1_wr_lk & 0x1) << 15) |
		  ((p->user_key1_crc_lk & 0x1) << 14) |
		  ((p->user_key0_wr_lk & 0x1) << 13) |
		  ((p->user_key0_crc_lk & 0x1) << 12) |
		  ((p->aes_wr_lk & 0x1) << 11) |
		  ((p->aes_crc_lk & 0x3) << 9) |
		  ((p->ppk2_wr_lk & 0x1) << 8) |
		  ((p->ppk1_wr_lk & 0x1) << 7) |
		  ((p->ppk0_wr_lk & 0x1) << 6) |
		  ((p->jtag_dis & 0x1) << 2) |
		  ((p->jtag_err_out_dis & 0x1) << 1) |
		  (p->aes_dis & 0x1);

	return do_write_efuses_value(EFUSE_WRITE_SEC_CTRL_BITS, val);
}

TEE_Result versal_efuse_write_misc(struct versal_efuse_misc_ctrl_bits *p)
{
	uint32_t val = 0;

	if (p == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	val = ((p->glitch_det_halt_boot_en & 0x3) << 30) |
		  ((p->glitch_det_rom_monitor_en & 0x1) << 29) |
		  ((p->halt_boot_error & 0x3) << 21) |
		  ((p->halt_boot_env & 0x3) << 19) |
		  ((p->crypto_kat_en & 0x1) << 15) |
		  ((p->lbist_en & 0x1) << 14) |
		  ((p->safety_mission_en & 0x1) << 8) |
		  ((p->ppk2_invalid & 0x3) << 6) |
		  ((p->ppk1_invalid & 0x3) << 4) |
		  ((p->ppk0_invalid & 0x3) << 2);

	return do_write_efuses_value(EFUSE_WRITE_MISC_CTRL_BITS, val);
}

TEE_Result versal_efuse_write_glitch_cfg(struct versal_efuse_glitch_cfg_bits
					 *p)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result versal_efuse_write_boot_env(struct versal_efuse_boot_env_ctrl_bits
				       *p)
{
	uint32_t val = 0;

	if (p == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	val = ((p->sysmon_temp_en & 0x1) << 21) |
		  ((p->sysmon_volt_en & 0x1) << 20) |
		  ((p->sysmon_temp_hot & 0x3) << 17) |
		  ((p->sysmon_volt_pmc & 0x3) << 12) |
		  ((p->sysmon_volt_pslp & 0x3) << 10) |
		  ((p->sysmon_volt_soc & 0x3) << 8) |
		  (p->sysmon_temp_cold & 0x2);

	return do_write_efuses_value(EFUSE_WRITE_BOOT_ENV_CTRL_BITS, val);
}

TEE_Result versal_efuse_write_sec_misc1(struct versal_efuse_sec_misc1_bits *p)
{
	uint32_t val = 0;

	if (p == NULL)
		return TEE_ERROR_BAD_PARAMETERS;

	val = ((p->lpd_mbist_en & 0x7) << 10) |
		  ((p->pmc_mbist_en & 0x7) << 7) |
		  ((p->lpd_noc_sc_en & 0x7) << 4) |
		  ((p->sysmon_volt_mon_en & 0x3) << 2) |
		  (p->sysmon_temp_mon_en & 0x3);

	return do_write_efuses_value(EFUSE_WRITE_MISC1_CTRL_BITS, val);
}

TEE_Result versal_efuse_write_offchip_ids(uint32_t id)
{
	return do_write_efuses_value(EFUSE_WRITE_OFFCHIP_REVOKE_ID, id);
}

TEE_Result versal_efuse_write_revoke_ppk(enum versal_nvm_ppk_type type)
{
	struct versal_efuse_misc_ctrl_bits misc_ctrl;

	memset(&misc_ctrl, 0, sizeof(struct versal_efuse_misc_ctrl_bits));

	switch (type) {
	case EFUSE_PPK0:
		misc_ctrl.ppk0_invalid = 0x3;
		break;
	case EFUSE_PPK1:
		misc_ctrl.ppk1_invalid = 0x3;
		break;
	case EFUSE_PPK2:
		misc_ctrl.ppk2_invalid = 0x3;
		break;
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return versal_efuse_write_misc(&misc_ctrl);
}

TEE_Result versal_efuse_write_revoke_id(uint32_t id)
{
	return do_write_efuses_value(EFUSE_WRITE_REVOCATION_ID, id);
}

TEE_Result versal_efuse_write_puf_as_user_fuse(struct versal_efuse_puf_user_fuse
					       *p)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}

TEE_Result versal_efuse_write_puf(struct versal_efuse_puf_header *buf)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
#else
TEE_Result versal_efuse_read_user_data(uint32_t *buf, size_t len,
				       uint32_t first, size_t num)
{
	struct versal_efuse_user_data cfg __aligned_efuse = {
		.start = first,
		.num = num,
	};
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_USER_FUSES,
	};
	void *rsp = NULL;

	if (first + num > EFUSE_MAX_USER_FUSES || len < num * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	rsp = alloc_cache_aligned(1024);
	if (!rsp)
		return TEE_ERROR_OUT_OF_MEMORY;

	req.ibuf[0].buf = &cfg;
	req.ibuf[0].len = sizeof(cfg);
	req.ibuf[1].buf = rsp;
	req.ibuf[1].len = 1024;

	cfg.addr = virt_to_phys((void *)rsp);

	if (versal_nvm_read(&req)) {
		free(rsp);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, rsp, num * sizeof(uint32_t));
	free(rsp);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_dna(uint32_t *buf, size_t len)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_DNA,
	};

	if (len < EFUSE_DNA_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_DNA_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_iv(uint32_t *buf, size_t len,
				enum versal_nvm_iv_type type)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_IV,
		.iv_type = type,
	};

	if (len < EFUSE_IV_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_IV_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_ppk(uint32_t *buf, size_t len,
				 enum versal_nvm_ppk_type type)
{
	struct versal_nvm_read_req req = {
		req.efuse_id = EFUSE_READ_PPK_HASH,
		.ppk_type = type,
	};

	if (len < EFUSE_PPK_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_PPK_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_write_user_data(uint32_t *buf, size_t len,
					uint32_t first, size_t num)
{
	uint32_t lbuf[EFUSE_MAX_USER_FUSES] __aligned_efuse = { 0 };
	struct versal_efuse_user_data cfg __aligned_efuse = {
		.addr = (uintptr_t)lbuf,
		.start = first,
		.num = num,
	};
	struct versal_nvm_write_req __aligned_efuse req = {
		.data.user_fuse_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};
	size_t i = 0;

	if (first + num > EFUSE_MAX_USER_FUSES || len  < num * sizeof(uint32_t))
		return TEE_ERROR_BAD_PARAMETERS;

	req.data.user_fuse_addr = virt_to_phys((void *)req.data.user_fuse_addr);
	cfg.addr = virt_to_phys(lbuf);

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);
	req.ibuf[2].buf = lbuf;
	req.ibuf[2].len = sizeof(lbuf);

	for (i = 0; i < cfg.num; i++)
		lbuf[i] = buf[i];

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_aes_keys(struct versal_efuse_aes_keys *keys)
{
	struct versal_efuse_aes_keys cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.aes_key_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, keys, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_ppk_hash(struct versal_efuse_ppk_hash *hash)
{
	struct versal_efuse_ppk_hash cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.ppk_hash_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, hash, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_iv(struct versal_efuse_ivs *p)
{
	struct versal_efuse_ivs cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.iv_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_dec_only(struct versal_efuse_dec_only *p)
{
	struct versal_efuse_dec_only cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.dec_only_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_sec(struct versal_efuse_sec_ctrl_bits *p)
{
	struct versal_efuse_sec_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.sec_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_misc(struct versal_efuse_misc_ctrl_bits *p)
{
	struct versal_efuse_misc_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.misc_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_glitch_cfg(struct versal_efuse_glitch_cfg_bits *p)
{
	struct versal_efuse_glitch_cfg_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.glitch_cfg_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_boot_env(struct versal_efuse_boot_env_ctrl_bits
				       *p)
{
	struct versal_efuse_boot_env_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.boot_env_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_sec_misc1(struct versal_efuse_sec_misc1_bits *p)
{
	struct versal_efuse_sec_misc1_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.misc1_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_offchip_ids(struct versal_efuse_offchip_ids *p)
{
	struct versal_efuse_offchip_ids cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.offchip_id_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	memcpy(&cfg, p, sizeof(cfg));

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_revoke_ppk(enum versal_nvm_ppk_type type)
{
	struct versal_efuse_misc_ctrl_bits cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.misc_ctrl_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};

	req.data.misc_ctrl_addr = virt_to_phys((void *)req.data.misc_ctrl_addr);
	if (type == EFUSE_PPK0)
		cfg.ppk0_invalid = 1;
	else if (type == EFUSE_PPK1)
		cfg.ppk1_invalid = 1;
	else if (type == EFUSE_PPK2)
		cfg.ppk2_invalid = 1;
	else
		return TEE_ERROR_BAD_PARAMETERS;

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_write_revoke_id(uint32_t id)
{
	struct versal_efuse_revoke_ids cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.data.revoke_id_addr = virt_to_phys(&cfg),
		.data.env_mon_dis_flag = 1,
		.efuse_id = EFUSE_WRITE,
	};
	uint32_t row = 0;
	uint32_t bit = 0;

	row = id >> (NVM_WORD_LEN + 1);
	bit = id & (NVM_WORD_LEN - 1);

	cfg.revoke_id[row] = BIT(bit);
	cfg.prgm_revoke_id = 1;

	req.ibuf[0].buf = &req.data;
	req.ibuf[0].len = sizeof(req.data);
	req.ibuf[1].buf = &cfg;
	req.ibuf[1].len = sizeof(cfg);

	return versal_nvm_write(&req);
}

TEE_Result versal_efuse_read_revoke_id(uint32_t *buf, size_t len,
				       enum versal_nvm_revocation_id id)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_REVOCATION_ID,
		.revocation_id = id,
	};

	if (len < EFUSE_REVOCATION_ID_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_REVOCATION_ID_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_misc_ctrl(struct versal_efuse_misc_ctrl_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_MISC_CTRL,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_sec_ctrl(struct versal_efuse_sec_ctrl_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_SEC_CTRL,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_sec_misc1(struct versal_efuse_sec_misc1_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_SEC_MISC1,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result
versal_efuse_read_boot_env_ctrl(struct versal_efuse_boot_env_ctrl_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_BOOT_ENV_CTRL,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_offchip_revoke_id(uint32_t *buf, size_t len,
					       enum versal_nvm_offchip_id id)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_OFFCHIP_REVOCATION_ID,
		.offchip_id = id,
	};

	if (len < EFUSE_OFFCHIP_REVOCATION_ID_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_REVOCATION_ID_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_dec_only(uint32_t *buf, size_t len)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_DEC_EFUSE_ONLY,
	};

	if (len < EFUSE_DEC_ONLY_LEN)
		return TEE_ERROR_BAD_PARAMETERS;

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), EFUSE_DEC_ONLY_LEN);
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result
versal_efuse_read_puf_sec_ctrl(struct versal_efuse_puf_sec_ctrl_bits *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_PUF_SEC_CTRL,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_read_puf(struct versal_efuse_puf_header *buf)
{
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_PUF,
	};

	if (versal_alloc_read_buffer(&req))
		return TEE_ERROR_OUT_OF_MEMORY;

	memcpy(versal_get_read_buffer(&req), buf, sizeof(*buf));

	if (versal_nvm_read(&req)) {
		versal_free_read_buffer(&req);
		return TEE_ERROR_GENERIC;
	}

	memcpy(buf, versal_get_read_buffer(&req), sizeof(*buf));
	versal_free_read_buffer(&req);

	return TEE_SUCCESS;
}

/*
 *  This functionality requires building the PLM with XNVM_ACCESS_PUF_USER_DATA
 *  Calls will fail otherwise.
 *  When available, efuse_read_puf becomes unavailable.
 */
TEE_Result
versal_efuse_read_puf_as_user_fuse(struct versal_efuse_puf_user_fuse *p)
{
	uint32_t fuses[PUF_EFUSES_WORDS]__aligned_efuse = { 0 };
	struct versal_efuse_puf_fuse_addr lbuf __aligned_efuse = {
		.env_monitor_dis = p->env_monitor_dis,
		.prgm_puf_fuse = p->prgm_puf_fuse,
		.start_row = p->start_row,
		.num_rows = p->num_rows,
		.data_addr = virt_to_phys(fuses),
	};
	struct versal_nvm_read_req req = {
		.efuse_id = EFUSE_READ_PUF_USER_FUSES,
	};

	req.ibuf[0].buf = &lbuf;
	req.ibuf[0].len = sizeof(lbuf);
	req.ibuf[1].buf = fuses;
	req.ibuf[1].len = sizeof(fuses);

	if (versal_nvm_read(&req))
		return TEE_ERROR_GENERIC;

	memcpy(p->data_addr, fuses, sizeof(fuses));

	return TEE_SUCCESS;
}

/*
 *  This functionality requires building the PLM with XNVM_ACCESS_PUF_USER_DATA.
 *  Calls will fail otherwise.
 *  When available, efuse_write_puf becomes unavailable.
 */
TEE_Result
versal_efuse_write_puf_as_user_fuse(struct versal_efuse_puf_user_fuse *p)
{
	uint32_t fuses[PUF_EFUSES_WORDS]__aligned_efuse = { 0 };
	struct versal_efuse_puf_fuse_addr lbuf __aligned_efuse  = {
		.env_monitor_dis = p->env_monitor_dis,
		.prgm_puf_fuse = p->prgm_puf_fuse,
		.start_row = p->start_row,
		.num_rows = p->num_rows,
		.data_addr = virt_to_phys(fuses),
	};
	struct versal_nvm_write_req req = {
		.efuse_id = EFUSE_PUF_USER_FUSE_WRITE,
	};

	memcpy(fuses, p->data_addr, sizeof(p->data_addr));

	req.ibuf[0].buf = &lbuf;
	req.ibuf[0].len = sizeof(lbuf);
	req.ibuf[1].buf = fuses;
	req.ibuf[1].len = sizeof(fuses);

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}

TEE_Result versal_efuse_write_puf(struct versal_efuse_puf_header *buf)
{
	struct versal_efuse_puf_header cfg __aligned_efuse = { };
	struct versal_nvm_write_req req __aligned_efuse = {
		.efuse_id = EFUSE_WRITE_PUF,
	};

	memcpy(&cfg, buf, sizeof(*buf));

	req.ibuf[0].buf = &cfg;
	req.ibuf[0].len = sizeof(cfg);

	if (versal_nvm_write(&req))
		return TEE_ERROR_GENERIC;

	return TEE_SUCCESS;
}
#endif
