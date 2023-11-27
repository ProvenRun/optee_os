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

TEE_Result versal_ecc_kat(void)
{
	return TEE_ERROR_NOT_IMPLEMENTED;
}
