// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2023 ProvenRun SAS
 */
#include <kernel/pseudo_ta.h>
#include <kernel/tee_time.h>
#include <drivers/versal_gpio.h>
#include <drivers/versal_nvm.h>
#include <drivers/versal_puf.h>
#include <drivers/gpio.h>
#include <crypto/crypto.h>

#define VERSAL_TEST_PTA_NAME "gpio.pta"

#define VERSAL_TEST_PTA_UUID { 0xf60b2cbc, 0xd14e, 0x4ffb, \
	{ 0x8f, 0xdc, 0x25, 0x86, 0xfb, 0x20, 0x3d, 0xf0 } }

#define VERSAL_TEST_PTA_TEST_PMC_GPIO		0x00
#define VERSAL_TEST_PTA_TEST_PS_GPIO		0x01
#define VERSAL_TEST_PTA_TEST_NVM			0x10
#define VERSAL_TEST_PTA_TEST_PUF			0x20
#define VERSAL_TEST_PTA_TEST_PKI			0x40

#define GPIO_TEST_PIN_ID 			56

#define BBRAM_USER_DATA				0xdeadbeef

static TEE_Result test_gpio(struct versal_gpio_chip *chip)
{
	struct gpio pin;

	pin.chip = &chip->chip;
	pin.dt_flags = 0;

	/* Go beyond first bank to test GPIO number <-> bank/pin */
	pin.pin = GPIO_TEST_PIN_ID;

	/* Set GPIO pin to output high */
	gpio_set_direction(&pin, GPIO_DIR_OUT);
	gpio_set_value(&pin, GPIO_LEVEL_HIGH);

	return TEE_SUCCESS;
}

static TEE_Result test_pmc_gpio(void)
{
	struct versal_gpio_chip chip = {};
	TEE_Result ret = TEE_SUCCESS;

	ret = versal_gpio_pmc_init(&chip);
	if (ret)
		return ret;

	return test_gpio(&chip);
}

static TEE_Result test_ps_gpio(void)
{
	struct versal_gpio_chip chip = {};
	TEE_Result ret = TEE_SUCCESS;

	ret = versal_gpio_ps_init(&chip);
	if (ret)
		return ret;

	return test_gpio(&chip);
}

static TEE_Result test_nvm(void)
{
	TEE_Result ret = TEE_SUCCESS;
	uint32_t dna[EFUSE_DNA_LEN];
	uint32_t val;

	/* Try and read DNA */
	ret = versal_efuse_read_dna(dna, EFUSE_DNA_LEN);
	if (ret) {
		EMSG("Reading DNA returned error 0x%08x", ret);
		return ret;
	}

	/* Test BBRAM access */
	ret = versal_bbram_zeroize();
	if (ret) {
		EMSG("Clearing BBRAM returned error 0x%08x", ret);
		return ret;
	}

	ret = versal_bbram_write_user_data(BBRAM_USER_DATA);
	if (ret) {
		EMSG("Writing user data to BBRAM returned error 0x%08x", ret);
		return ret;
	}

	ret = versal_bbram_read_user_data(&val);
	if (ret) {
		EMSG("Reading user data from BBRAM returned error 0x%08x", ret);
		return ret;
	}

	if (val != BBRAM_USER_DATA) {
		EMSG("Invalid value read from BBRAM: 0x%08x", val);
		return TEE_ERROR_GENERIC;
	}

	return ret;
}

static TEE_Result test_puf(void)
{
	TEE_Result ret = TEE_SUCCESS;

	ret = versal_puf_check_api(VERSAL_PUF_REGISTER);
	if (ret) {
		EMSG("Checking PUF Register API returned error 0x%08x", ret);
		return ret;
	}

	ret = versal_puf_check_api(VERSAL_PUF_REGENERATE);
	if (ret) {
		EMSG("Checking PUF Regenerate API returned error 0x%08x", ret);
		return ret;
	}

	ret = versal_puf_check_api(VERSAL_PUF_CLEAR_ID);
	if (ret) {
		EMSG("Checking PUF Clear ID API returned error 0x%08x", ret);
		return ret;
	}

	return ret;
}

static TEE_Result test_pki(uint32_t curve)
{
	struct ecc_keypair key;
	struct ecc_public_key pkey;
	TEE_Result ret = TEE_SUCCESS;

	uint8_t msg[TEE_SHA512_HASH_SIZE] = { };
	uint8_t sig[(TEE_SHA512_HASH_SIZE + 2) * 2] = { };

	size_t bytes;
	size_t bits;
	uint32_t algo;
	size_t len = (TEE_SHA512_HASH_SIZE + 2) * 2;

	switch (curve) {
		case TEE_ECC_CURVE_NIST_P256:
			bits = 256;
			bytes = 32;
			algo = TEE_ALG_ECDSA_SHA256;
			break;

		case TEE_ECC_CURVE_NIST_P384:
			bits = 384;
			bytes = 48;
			algo = TEE_ALG_ECDSA_SHA384;
			break;

		case TEE_ECC_CURVE_NIST_P521:
			bits = 521;
			bytes = 66;
			algo = TEE_ALG_ECDSA_SHA512;
			break;

		default:
			return TEE_ERROR_NOT_SUPPORTED;
	}

	len = bytes * 2;

	ret = crypto_acipher_alloc_ecc_keypair(&key, TEE_TYPE_ECDSA_KEYPAIR, bits);
	if (ret) {
		DMSG("Error allocating ECDSA keypair 0x%" PRIx32, ret);
		return ret;
	}
	key.curve = curve;

	ret = crypto_acipher_gen_ecc_key(&key, bits);
	if (ret) {
		DMSG("Error generating ECDSA keypair 0x%" PRIx32, ret);
		goto error;
	}

	ret = crypto_acipher_ecc_sign(algo, &key, msg, bytes, sig, &len);
	if (ret) {
		DMSG("Error signing message 0x%" PRIx32, ret);
		goto error;
	}

	/*
	 * Only copy the public part of the key.
	 * OP-TEE doesn't allow to fill in the ecc_public_key.ops field
	 * easily, so let's allocate a dummy public key then modify it
	 * to match our previously generated private key.
	 */
	ret = crypto_acipher_alloc_ecc_public_key(&pkey, TEE_TYPE_ECDSA_PUBLIC_KEY, bits);
	if (ret) {
		DMSG("Error allocating ECDSA public key 0x%" PRIx32, ret);
		goto error;
	}

	crypto_bignum_free(pkey.x);
	crypto_bignum_free(pkey.y);
	pkey.x = key.x;
	pkey.y = key.y;
	pkey.curve = key.curve;

	ret = crypto_acipher_ecc_verify(algo, &pkey, msg, bytes, sig, bytes * 2);
	if (ret)
		DMSG("Error verifying signature 0x%" PRIx32, ret);

error:
	crypto_bignum_free(key.x);
	crypto_bignum_free(key.y);
	crypto_bignum_free(key.d);
	return ret;
}

static TEE_Result invokeCommandEntryPoint(void *sess_ctx __unused,
					  uint32_t cmd_id,
					  uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	switch (cmd_id) {
		case VERSAL_TEST_PTA_TEST_PMC_GPIO:
			return test_pmc_gpio();
		case VERSAL_TEST_PTA_TEST_PS_GPIO:
			return test_ps_gpio();
		case VERSAL_TEST_PTA_TEST_NVM:
			return test_nvm();
		case VERSAL_TEST_PTA_TEST_PUF:
			return test_puf();
		case VERSAL_TEST_PTA_TEST_PKI:
			if (param_types != exp_param_types)
				return TEE_ERROR_BAD_PARAMETERS;
			return test_pki(params[0].value.a);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}

pseudo_ta_register(.uuid = VERSAL_TEST_PTA_UUID, .name = VERSAL_TEST_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
