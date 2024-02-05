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

#define VERSAL_TEST_PTA_NAME "versal-test.pta"

#define VERSAL_TEST_PTA_UUID { 0xf60b2cbc, 0xd14e, 0x4ffb, \
	{ 0x8f, 0xdc, 0x25, 0x86, 0xfb, 0x20, 0x3d, 0xf0 } }

#define VERSAL_TEST_PTA_TEST_PMC_GPIO		0x00
#define VERSAL_TEST_PTA_TEST_PS_GPIO		0x01
#define VERSAL_TEST_PTA_TEST_NVM			0x10
#define VERSAL_TEST_PTA_TEST_PUF			0x20
#define VERSAL_TEST_PTA_TEST_PKI			0x40
#define VERSAL_TEST_PTA_BENCH_PKI			0x50
#define VERSAL_TEST_PTA_BENCH_PKI_CLIENT	0x60

#define GPIO_TEST_PIN_ID 			56

#define BBRAM_USER_DATA				0xdeadbeef

struct versal_test_pta_ctx
{
	struct ecc_keypair key;
	struct ecc_public_key pkey;
	uint8_t msg[TEE_SHA512_HASH_SIZE];
	uint8_t sig[(TEE_SHA512_HASH_SIZE + 2) * 2];
};

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

static TEE_Result get_ecc_params(uint32_t curve, uint32_t *algo,
					  size_t *bytes, size_t *bits)
{
	assert(algo != NULL);
	assert(bytes != NULL);
	assert(bits != NULL);

	switch (curve) {
		case TEE_ECC_CURVE_NIST_P256:
			*bits = 256;
			*bytes = 32;
			*algo = TEE_ALG_ECDSA_SHA256;
			break;

		case TEE_ECC_CURVE_NIST_P384:
			*bits = 384;
			*bytes = 48;
			*algo = TEE_ALG_ECDSA_SHA384;
			break;

		case TEE_ECC_CURVE_NIST_P521:
			*bits = 521;
			*bytes = 66;
			*algo = TEE_ALG_ECDSA_SHA512;
			break;

		default:
			return TEE_ERROR_NOT_SUPPORTED;
	}

	return TEE_SUCCESS;
}

static TEE_Result test_pki(void *sess_ctx, uint32_t curve)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_test_pta_ctx *ctx = sess_ctx;

	size_t bytes;
	size_t bits;
	uint32_t algo;
	size_t len = (TEE_SHA512_HASH_SIZE + 2) * 2;

	assert(ctx != NULL);

	if (ctx->key.curve != curve)
		return TEE_ERROR_BAD_STATE;

	ret = get_ecc_params(curve, &algo, &bytes, &bits);
	if (ret)
		return ret;

	len = bytes * 2;

	ret = crypto_acipher_ecc_sign(algo, &ctx->key, ctx->msg, bytes, ctx->sig, &len);
	if (ret) {
		DMSG("Error signing message 0x%" PRIx32, ret);
		return ret;
	}

	ret = crypto_acipher_ecc_verify(algo, &ctx->pkey, ctx->msg, bytes, ctx->sig, bytes * 2);
	if (ret)
		DMSG("Error verifying signature 0x%" PRIx32, ret);

	return ret;
}

#define OP_SIGN 	0
#define OP_VERIFY	1

static TEE_Result bench_pki_client(void *sess_ctx, uint32_t curve, uint32_t op)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_test_pta_ctx *ctx = sess_ctx;
	size_t bytes;
	size_t bits;
	uint32_t algo;
	size_t len = (TEE_SHA512_HASH_SIZE + 2) * 2;

	assert(ctx != NULL);

	if (ctx->key.curve != curve)
		return TEE_ERROR_BAD_STATE;

	ret = get_ecc_params(curve, &algo, &bytes, &bits);
	if (ret)
		return ret;

	len = bytes * 2;

	switch (op) {
		case OP_SIGN:
			ret = crypto_acipher_ecc_sign(algo, &ctx->key, ctx->msg, bytes, ctx->sig, &len);
			break;
		case OP_VERIFY:
			ret = crypto_acipher_ecc_verify(algo, &ctx->pkey, ctx->msg, bytes, ctx->sig, bytes * 2);
			break;
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}

	return ret;
}

static TEE_Result bench_pki(void *sess_ctx, uint32_t curve, uint32_t op, uint32_t *millis)
{
	TEE_Time start, end;
	TEE_Result ret = TEE_SUCCESS;

	assert(millis != NULL);

	ret = tee_time_get_sys_time(&start);
	if (ret) {
		DMSG("error requesting system time (ret = 0x%" PRIx32 ")", ret);
		return ret;
	}

	ret = bench_pki_client(sess_ctx, curve, op);
	if (ret)
		return ret;

	ret = tee_time_get_sys_time(&end);
	if (ret) {
		DMSG("error requesting system time (ret = 0x%" PRIx32 ")", ret);
		return ret;
	}

	/* Compute delta time */
	*millis =
		(end.seconds * 1000 + end.millis) - (start.seconds * 1000 + start.millis);

	return ret;
}

#define PARAM_TYPES_NOPARAMS \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE, \
					TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)
#define PARAM_TYPES_INPUT \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_NONE, \
					TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)
#define PARAM_TYPES_INOUT \
	TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT, TEE_PARAM_TYPE_VALUE_OUTPUT, \
					TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE)

static TEE_Result invokeCommandEntryPoint(void *sess_ctx,
					  uint32_t cmd_id,
					  uint32_t param_types,
					  TEE_Param params[TEE_NUM_PARAMS])
{

	switch (cmd_id) {
		case VERSAL_TEST_PTA_TEST_PMC_GPIO:
			if (param_types != PARAM_TYPES_NOPARAMS)
				return TEE_ERROR_BAD_PARAMETERS;
			return test_pmc_gpio();
		case VERSAL_TEST_PTA_TEST_PS_GPIO:
			if (param_types != PARAM_TYPES_NOPARAMS)
				return TEE_ERROR_BAD_PARAMETERS;
			return test_ps_gpio();
		case VERSAL_TEST_PTA_TEST_NVM:
			if (param_types != PARAM_TYPES_NOPARAMS)
				return TEE_ERROR_BAD_PARAMETERS;
			return test_nvm();
		case VERSAL_TEST_PTA_TEST_PUF:
			if (param_types != PARAM_TYPES_NOPARAMS)
				return TEE_ERROR_BAD_PARAMETERS;
			return test_puf();
		case VERSAL_TEST_PTA_TEST_PKI:
			if (param_types != PARAM_TYPES_INPUT)
				return TEE_ERROR_BAD_PARAMETERS;
			return test_pki(sess_ctx, params[0].value.a);
		case VERSAL_TEST_PTA_BENCH_PKI:
			if (param_types != PARAM_TYPES_INOUT)
				return TEE_ERROR_BAD_PARAMETERS;
			return bench_pki(sess_ctx, params[0].value.a, params[0].value.b,
						   &params[1].value.a);
		case VERSAL_TEST_PTA_BENCH_PKI_CLIENT:
			if (param_types != PARAM_TYPES_INPUT)
				return TEE_ERROR_BAD_PARAMETERS;
			return bench_pki_client(sess_ctx, params[0].value.a,
						   params[0].value.b);
		default:
			return TEE_ERROR_BAD_PARAMETERS;
	}
}

static TEE_Result openSessionEntryPoint(uint32_t params_types,
					   TEE_Param params[TEE_NUM_PARAMS], void **sess_ctx)
{
	TEE_Result ret = TEE_SUCCESS;
	struct versal_test_pta_ctx *ctx = NULL;
	size_t bytes;
	size_t bits;
	uint32_t algo;
	uint32_t curve;

	if (params_types == 0)
		return TEE_SUCCESS;

	if (params_types != PARAM_TYPES_INPUT)
		return TEE_ERROR_BAD_PARAMETERS;

	ctx = malloc(sizeof(struct versal_test_pta_ctx));
	if (ctx == NULL)
		return TEE_ERROR_OUT_OF_MEMORY;

	curve = params[0].value.a;

	ret = get_ecc_params(curve, &algo, &bytes, &bits);
	if (ret) {
		free(ctx);
		return ret;
	}

	ret = crypto_acipher_alloc_ecc_keypair(&ctx->key, TEE_TYPE_ECDSA_KEYPAIR, bits);
	if (ret) {
		DMSG("Error allocating ECDSA keypair 0x%" PRIx32, ret);
		free(ctx);
		return ret;
	}
	ctx->key.curve = curve;

	ret = crypto_acipher_gen_ecc_key(&ctx->key, bits);
	if (ret) {
		DMSG("Error generating ECDSA keypair 0x%" PRIx32, ret);
		goto error;
	}

	/*
	 * Only copy the public part of the key.
	 * OP-TEE doesn't allow to fill in the ecc_public_key.ops field
	 * easily, so let's allocate a dummy public key then modify it
	 * to match our previously generated private key.
	 */
	ret = crypto_acipher_alloc_ecc_public_key(&ctx->pkey, TEE_TYPE_ECDSA_PUBLIC_KEY, bits);
	if (ret) {
		DMSG("Error allocating ECDSA public key 0x%" PRIx32, ret);
		goto error;
	}

	crypto_bignum_free(ctx->pkey.x);
	crypto_bignum_free(ctx->pkey.y);
	ctx->pkey.x = ctx->key.x;
	ctx->pkey.y = ctx->key.y;
	ctx->pkey.curve = ctx->key.curve;

	*sess_ctx = ctx;
	return TEE_SUCCESS;

error:
	crypto_bignum_free(ctx->key.x);
	crypto_bignum_free(ctx->key.y);
	crypto_bignum_free(ctx->key.d);
	free(ctx);

	return ret;
}

static void closeSessionEntryPoint(void *sess_ctx)
{
	struct versal_test_pta_ctx *ctx = sess_ctx;

	if (ctx == NULL)
		return;

	crypto_bignum_free(ctx->key.d);
	crypto_bignum_free(ctx->key.x);
	crypto_bignum_free(ctx->key.y);

	free(ctx);
}

pseudo_ta_register(.uuid = VERSAL_TEST_PTA_UUID, .name = VERSAL_TEST_PTA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = openSessionEntryPoint,
		   .close_session_entry_point = closeSessionEntryPoint,
		   .invoke_command_entry_point = invokeCommandEntryPoint);
