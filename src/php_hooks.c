/**
 * PHP Execution Hooks for security_guard
 *
 * Intercepts PHP function calls by hooking into zend_execute_ex.
 * Implements specific tracking for cURL handles and routes calls to the policy engine.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#include "php_hooks.h"
#include "policy_engine.h"
#include "network_policy.h"
#include "logger.h"
#include "utils.h"
#include <string.h>

void (*sg_original_execute_ex)(zend_execute_data *execute_data) = NULL;
void (*sg_original_execute_internal)(zend_execute_data *execute_data, zval *return_value) = NULL;

static void sg_call_original(zend_execute_data *execute_data, zval *return_value, int is_internal);

/* ---- curl handle tracking ---- */

/**
 * Destructor for cURL handle tracking structures.
 *
 * @param zv Pointer to the zval containing the sg_curl_handle_t.
 */
static void sg_curl_handle_dtor(zval *zv)
{
	sg_curl_handle_t *h = (sg_curl_handle_t *)Z_PTR_P(zv);
	if (h) {
		if (h->url) efree(h->url);
		efree(h);
	}
}

/* Build a stable string key from a zval (resource/object ID) */
/**
 * Generates a unique hash table key for a cURL handle (object or resource).
 *
 * @param handle The zval containing the cURL handle.
 * @param key Output buffer for the key string.
 * @param key_len Size of the key buffer.
 */
static void sg_curl_handle_key(zval *handle, char *key, size_t key_len)
{
	if (Z_TYPE_P(handle) == IS_OBJECT) {
		snprintf(key, key_len, "obj_%u", Z_OBJ_HANDLE_P(handle));
	} else if (Z_TYPE_P(handle) == IS_RESOURCE) {
		snprintf(key, key_len, "res_%d", Z_RES_HANDLE_P(handle));
	} else {
		snprintf(key, key_len, "unk_%p", (void *)handle);
	}
}

/**
 * Registers a new cURL handle in the tracking table.
 *
 * @param handle The cURL handle zval.
 * @param url Initial URL if provided during curl_init.
 */
void sg_curl_track_init(zval *handle, const char *url)
{
	if (!handle || !SG_G(curl_handles)) return;

	char key[64];
	sg_curl_handle_key(handle, key, sizeof(key));

	sg_curl_handle_t *h = ecalloc(1, sizeof(sg_curl_handle_t));
	if (url && *url) h->url = estrdup(url);

	zend_hash_str_update_ptr(SG_G(curl_handles), key, strlen(key), h);
}

/**
 * Tracks a curl_setopt call, specifically capturing the CURLOPT_URL.
 *
 * @param handle The cURL handle zval.
 * @param option The option ID.
 * @param value The value zval for the option.
 */
void sg_curl_track_setopt(zval *handle, zend_long option, zval *value)
{
	if (!handle || !SG_G(curl_handles)) return;
	/* CURLOPT_URL = 10002 */
	if (option != 10002) return;
	if (!value || Z_TYPE_P(value) != IS_STRING) return;

	char key[64];
	sg_curl_handle_key(handle, key, sizeof(key));

	sg_curl_handle_t *h = zend_hash_str_find_ptr(SG_G(curl_handles), key, strlen(key));
	if (!h) {
		h = ecalloc(1, sizeof(sg_curl_handle_t));
		zend_hash_str_add_ptr(SG_G(curl_handles), key, strlen(key), h);
	}
	if (h->url) efree(h->url);
	h->url = estrdup(Z_STRVAL_P(value));
}

/**
 * Tracks a curl_setopt_array call, specifically capturing the CURLOPT_URL if present.
 *
 * @param handle The cURL handle zval.
 * @param options HashTable of cURL options.
 */
void sg_curl_track_setopt_array(zval *handle, HashTable *options)
{
	if (!options) return;
	zval *url_val = zend_hash_index_find(options, 10002); /* CURLOPT_URL */
	if (url_val && Z_TYPE_P(url_val) == IS_STRING) {
		sg_curl_track_setopt(handle, 10002, url_val);
	}
}

/**
 * Retrieves the tracked URL for a given cURL handle.
 *
 * @param handle The cURL handle zval.
 * @return const char* The tracked URL or NULL if not found.
 */
const char *sg_curl_get_url(zval *handle)
{
	if (!handle || !SG_G(curl_handles)) return NULL;
	char key[64];
	sg_curl_handle_key(handle, key, sizeof(key));
	sg_curl_handle_t *h = zend_hash_str_find_ptr(SG_G(curl_handles), key, strlen(key));
	return h ? h->url : NULL;
}

/**
 * Removes a cURL handle from the tracking table when it is closed.
 *
 * @param handle The cURL handle zval.
 */
void sg_curl_track_close(zval *handle)
{
	if (!handle || !SG_G(curl_handles)) return;
	char key[64];
	sg_curl_handle_key(handle, key, sizeof(key));
	zend_hash_str_del(SG_G(curl_handles), key, strlen(key));
}

/* ---- curl tracking interceptors ---- */

/**
 * Interceptor for the curl_init PHP function.
 * Tracks the handle and initial URL.
 *
 * @param execute_data Zend execution data.
 */
static void sg_handle_curl_init(zend_execute_data *execute_data, zval *return_value, int is_internal)
{
	/* curl_init(?string $url = null): CurlHandle */
	uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
	const char *url = NULL;
	if (argc >= 1) {
		zval *arg = ZEND_CALL_ARG(execute_data, 1);
		if (arg && Z_TYPE_P(arg) == IS_STRING) url = Z_STRVAL_P(arg);
	}
	/* We call original first, then register the handle. */
	sg_call_original(execute_data, return_value, is_internal);

	if (return_value && (Z_TYPE_P(return_value) == IS_OBJECT || Z_TYPE_P(return_value) == IS_RESOURCE)) {
		sg_curl_track_init(return_value, url);
	}
}

/**
 * Interceptor for the curl_setopt PHP function.
 * Tracks URL changes via CURLOPT_URL.
 *
 * @param execute_data Zend execution data.
 */
static void sg_handle_curl_setopt(zend_execute_data *execute_data, zval *return_value, int is_internal)
{
	uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
	if (argc >= 3) {
		zval *handle  = ZEND_CALL_ARG(execute_data, 1);
		zval *opt     = ZEND_CALL_ARG(execute_data, 2);
		zval *val     = ZEND_CALL_ARG(execute_data, 3);
		if (handle && opt && Z_TYPE_P(opt) == IS_LONG) {
			sg_curl_track_setopt(handle, Z_LVAL_P(opt), val);
		}
	}
	sg_call_original(execute_data, return_value, is_internal);
}

/**
 * Interceptor for the curl_setopt_array PHP function.
 * Tracks URL changes within the options array.
 *
 * @param execute_data Zend execution data.
 */
static void sg_handle_curl_setopt_array(zend_execute_data *execute_data, zval *return_value, int is_internal)
{
	uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
	if (argc >= 2) {
		zval *handle = ZEND_CALL_ARG(execute_data, 1);
		zval *opts   = ZEND_CALL_ARG(execute_data, 2);
		if (handle && opts && Z_TYPE_P(opts) == IS_ARRAY) {
			sg_curl_track_setopt_array(handle, Z_ARRVAL_P(opts));
		}
	}
	sg_call_original(execute_data, return_value, is_internal);
}

/**
 * Interceptor for the curl_close PHP function.
 * Cleans up the tracking entry.
 *
 * @param execute_data Zend execution data.
 */
static void sg_handle_curl_close(zend_execute_data *execute_data, zval *return_value, int is_internal)
{
	uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
	if (argc >= 1) {
		zval *handle = ZEND_CALL_ARG(execute_data, 1);
		if (handle) sg_curl_track_close(handle);
	}
	sg_call_original(execute_data, return_value, is_internal);
}

/* ---- main hook ---- */

/**
 * Helper to call the original execution function.
 */
static void sg_call_original(zend_execute_data *execute_data, zval *return_value, int is_internal)
{
	if (is_internal) {
		if (sg_original_execute_internal) {
			sg_original_execute_internal(execute_data, return_value);
		} else {
			execute_data->func->internal_function.handler(execute_data, return_value);
		}
	} else {
		if (sg_original_execute_ex) {
			sg_original_execute_ex(execute_data);
		}
	}
}

/**
 * Common interceptor logic for PHP execution.
 */
static void sg_execute_common(zend_execute_data *execute_data, zval *return_value, int is_internal)
{
	if (!SG_G(enabled) || SG_G(enforcement_mode) == SG_MODE_OFF) {
		sg_call_original(execute_data, return_value, is_internal);
		return;
	}

	const zend_function *func = execute_data->func;
	if (!func || !func->common.function_name) {
		sg_call_original(execute_data, return_value, is_internal);
		return;
	}

	const char *fname = ZSTR_VAL(func->common.function_name);

	if (!sg_is_monitored_function(fname)) {
		sg_call_original(execute_data, return_value, is_internal);
		return;
	}

	/* Handle curl tracking helpers */
	if (strcmp(fname, "curl_init") == 0) {
		sg_handle_curl_init(execute_data, return_value, is_internal);
		return;
	}
	if (strcmp(fname, "curl_setopt") == 0) {
		sg_handle_curl_setopt(execute_data, return_value, is_internal);
		return;
	}
	if (strcmp(fname, "curl_setopt_array") == 0) {
		sg_handle_curl_setopt_array(execute_data, return_value, is_internal);
		return;
	}
	if (strcmp(fname, "curl_close") == 0) {
		sg_handle_curl_close(execute_data, return_value, is_internal);
		return;
	}

	/* Evaluate policy */
	sg_decision_t *dec = sg_evaluate_call(fname, execute_data);
	if (!dec) {
		sg_call_original(execute_data, return_value, is_internal);
		return;
	}

	int allowed  = dec->allowed;
	int is_block = (SG_G(enforcement_mode) == SG_MODE_BLOCK);

	if (allowed || !is_block) {
		/* Execute the original function */
		sg_call_original(execute_data, return_value, is_internal);

		if (allowed && SG_G(log_allowed)) {
			sg_log_allow(dec);
		}
		if (!allowed && !is_block && SG_G(log_denied)) {
			sg_log_monitor_violation(dec);
		}
	} else {
		/* Block: do NOT call original */
		sg_block_call(fname, return_value, dec);
		if (SG_G(log_denied)) {
			sg_log_deny(dec);
		}
	}

	sg_decision_free(dec);
}

/**
 * Main interceptor for userland PHP execution.
 */
void sg_execute_ex(zend_execute_data *execute_data)
{
	sg_execute_common(execute_data, execute_data->return_value, 0);
}

/**
 * Interceptor for internal C functions.
 */
void sg_execute_internal(zend_execute_data *execute_data, zval *return_value)
{
	sg_execute_common(execute_data, return_value, 1);
}

/**
 * Installs the extension's execution hook.
 */
void sg_hooks_install(void)
{
	sg_original_execute_ex = zend_execute_ex;
	zend_execute_ex        = sg_execute_ex;

	sg_original_execute_internal = zend_execute_internal;
	zend_execute_internal        = sg_execute_internal;
}

/**
 * Restores the original pointers and uninstalls hooks.
 */
void sg_hooks_uninstall(void)
{
	if (zend_execute_ex == sg_execute_ex) {
		zend_execute_ex = sg_original_execute_ex;
	}
	sg_original_execute_ex = NULL;

	if (zend_execute_internal == sg_execute_internal) {
		zend_execute_internal = sg_original_execute_internal;
	}
	sg_original_execute_internal = NULL;

}
