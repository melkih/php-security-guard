/**
 * Main Extension File for security_guard
 *
 * This file defines the PHP extension structure, INI entries,
 * and the lifecycle hooks (MINIT, MSHUTDOWN, RINIT, RSHUTDOWN).
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "include/security_guard.h"
#include "include/php_hooks.h"
#include "include/config_loader.h"
#include "include/policy_engine.h"
#include "include/utils.h"
#include <string.h>

ZEND_DECLARE_MODULE_GLOBALS(security_guard)

/* ---- INI handling ---- */

/**
 * Parses the enforcement mode from the INI setting.
 * Possible values: 'off', 'monitor', 'block' (default).
 */
static void sg_parse_enforcement_mode(void)
{
	const char *m = SG_G(enforcement_mode_str);
	if (!m) { SG_G(enforcement_mode) = SG_MODE_BLOCK; return; }
	if (strcmp(m, "off")     == 0) SG_G(enforcement_mode) = SG_MODE_OFF;
	else if (strcmp(m, "monitor") == 0) SG_G(enforcement_mode) = SG_MODE_MONITOR;
	else SG_G(enforcement_mode) = SG_MODE_BLOCK;
}

/**
 * Parses the log scope from the INI setting.
 * Possible values: 'global', 'per_user' (default).
 */
static void sg_parse_log_scope(void)
{
	const char *s = SG_G(log_scope_str);
	if (s && strcmp(s, "global") == 0) SG_G(log_scope) = SG_LOG_SCOPE_GLOBAL;
	else SG_G(log_scope) = SG_LOG_SCOPE_PER_USER;
}

/**
 * Parses the log format from the INI setting.
 * Possible values: 'plain', 'jsonl' (default).
 */
static void sg_parse_log_format(void)
{
	const char *f = SG_G(log_format_str);
	if (f && strcmp(f, "plain") == 0) SG_G(log_format) = SG_LOG_FORMAT_PLAIN;
	else SG_G(log_format) = SG_LOG_FORMAT_JSONL;
}

/* ---- PHP_INI ---- */

PHP_INI_BEGIN()
	STD_PHP_INI_BOOLEAN("security_guard.enabled",             "1",   PHP_INI_SYSTEM, OnUpdateBool,   enabled,                    zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY("security_guard.enforcement_mode",      "block", PHP_INI_SYSTEM, OnUpdateString, enforcement_mode_str,       zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY("security_guard.allowed_commands_file", "/etc/security_guard/allowed_commands.conf", PHP_INI_SYSTEM, OnUpdateString, allowed_commands_file, zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY("security_guard.allowed_files_file",    "/etc/security_guard/allowed_files.conf",    PHP_INI_SYSTEM, OnUpdateString, allowed_files_file,    zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY("security_guard.allowed_network_file",  "/etc/security_guard/allowed_network.conf",  PHP_INI_SYSTEM, OnUpdateString, allowed_network_file,  zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_BOOLEAN("security_guard.log_allowed",         "0",   PHP_INI_SYSTEM, OnUpdateBool,   log_allowed,                zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_BOOLEAN("security_guard.log_denied",          "1",   PHP_INI_SYSTEM, OnUpdateBool,   log_denied,                 zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY("security_guard.log_scope",             "per_user", PHP_INI_SYSTEM, OnUpdateString, log_scope_str,          zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY("security_guard.log_path",              "/var/log/security_guard", PHP_INI_SYSTEM, OnUpdateString, log_path, zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY("security_guard.log_format",            "jsonl", PHP_INI_SYSTEM, OnUpdateString, log_format_str,           zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_BOOLEAN("security_guard.allow_wildcard_domains",              "1", PHP_INI_SYSTEM, OnUpdateBool, allow_wildcard_domains,              zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_BOOLEAN("security_guard.require_base_domain_for_wildcard",    "1", PHP_INI_SYSTEM, OnUpdateBool, require_base_domain_for_wildcard,    zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_BOOLEAN("security_guard.block_private_networks",              "1", PHP_INI_SYSTEM, OnUpdateBool, block_private_networks,              zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_BOOLEAN("security_guard.explicit_allow_overrides_private_block", "1", PHP_INI_SYSTEM, OnUpdateBool, explicit_allow_overrides_private_block, zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_BOOLEAN("security_guard.block_metadata_endpoints",            "1", PHP_INI_SYSTEM, OnUpdateBool, block_metadata_endpoints,            zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_BOOLEAN("security_guard.emit_php_warning",                    "1", PHP_INI_SYSTEM, OnUpdateBool, emit_php_warning,                    zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY("security_guard.block_message",         "Security policy blocked this operation", PHP_INI_SYSTEM, OnUpdateString, block_message,  zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY_EX("security_guard.config_reload_interval", "60",   PHP_INI_SYSTEM, OnUpdateLong,  config_reload_interval, zend_security_guard_globals, security_guard_globals, NULL)
	STD_PHP_INI_ENTRY_EX("security_guard.log_target_max_length",  "2048", PHP_INI_SYSTEM, OnUpdateLong,  log_target_max_length,  zend_security_guard_globals, security_guard_globals, NULL)
	STD_PHP_INI_BOOLEAN("security_guard.log_backtrace",       "0",   PHP_INI_SYSTEM, OnUpdateBool,   log_backtrace,              zend_security_guard_globals, security_guard_globals)
	STD_PHP_INI_ENTRY_EX("security_guard.log_rate_limit",         "1000", PHP_INI_SYSTEM, OnUpdateLong,  log_rate_limit,         zend_security_guard_globals, security_guard_globals, NULL)
PHP_INI_END()

/* ---- Module lifecycle ---- */

/**
 * Constructor for module globals.
 * Initializes all global variables to zero.
 *
 * @param globals Pointer to the globals structure.
 */
static void sg_globals_ctor(zend_security_guard_globals *globals)
{
	memset(globals, 0, sizeof(*globals));
}

/**
 * Destructor for module globals.
 *
 * @param globals Pointer to the globals structure.
 */
static void sg_globals_dtor(zend_security_guard_globals *globals)
{
	/* Nothing heap-allocated in globals at this level;
	   config/curl_handles are freed in MSHUTDOWN/RSHUTDOWN */
}

/**
 * Module initialization handler.
 * Sets up globals, registers INI entries, initializes the policy engine,
 * and installs PHP function hooks.
 */
PHP_MINIT_FUNCTION(security_guard)
{
	ZEND_INIT_MODULE_GLOBALS(security_guard, sg_globals_ctor, sg_globals_dtor);
	REGISTER_INI_ENTRIES();

	sg_parse_enforcement_mode();
	sg_parse_log_scope();
	sg_parse_log_format();

	sg_policy_engine_init();

	/* Load config now so RINIT is fast */
	SG_G(config) = sg_config_load();

	sg_hooks_install();

	return SUCCESS;
}

/**
 * Module shutdown handler.
 * Uninstalls hooks and frees global resources.
 */
PHP_MSHUTDOWN_FUNCTION(security_guard)
{
	sg_hooks_uninstall();
	sg_policy_engine_shutdown();

	if (SG_G(config)) {
		sg_config_free(SG_G(config));
		SG_G(config) = NULL;
	}

	UNREGISTER_INI_ENTRIES();
	return SUCCESS;
}

/**
 * Request initialization handler.
 * Checks for config reloads, resolves the effective user,
 * and initializes per-request data structures.
 */
PHP_RINIT_FUNCTION(security_guard)
{
#if defined(COMPILE_DL_SECURITY_GUARD) && defined(ZTS)
	ZEND_TSRMLS_CACHE_UPDATE();
#endif

	/* Check for config file changes once per request (avoids per-call overhead) */
	sg_config_reload_if_needed();

	/* Resolve effective user once per request */
	char user_buf[256] = {0};
	int uid = 0;
	sg_get_effective_user(user_buf, sizeof(user_buf), &uid);
	SG_G(current_user) = estrdup(user_buf);
	SG_G(current_uid)  = uid;
	SG_G(log_rate_count) = 0;

	/* curl handle table (per-request lifetime) */
	if (!SG_G(curl_handles)) {
		ALLOC_HASHTABLE(SG_G(curl_handles));
		zend_hash_init(SG_G(curl_handles), 8, NULL,
			/* dtor */ (dtor_func_t)NULL, 0);
	}

	/* Re-parse mode strings in case they were changed at runtime (edge case) */
	sg_parse_enforcement_mode();
	sg_parse_log_scope();
	sg_parse_log_format();

	return SUCCESS;
}

/**
 * Request shutdown handler.
 * Frees per-request allocated memory.
 */
PHP_RSHUTDOWN_FUNCTION(security_guard)
{
	if (SG_G(current_user)) {
		efree(SG_G(current_user));
		SG_G(current_user) = NULL;
	}

	if (SG_G(curl_handles)) {
		/* Free all tracked handles */
		sg_curl_handle_t *h;
		ZEND_HASH_FOREACH_PTR(SG_G(curl_handles), h) {
			if (h) {
				if (h->url) efree(h->url);
				efree(h);
			}
		} ZEND_HASH_FOREACH_END();

		zend_hash_destroy(SG_G(curl_handles));
		FREE_HASHTABLE(SG_G(curl_handles));
		SG_G(curl_handles) = NULL;
	}

	return SUCCESS;
}

/**
 * PHP info hook.
 * Displays information about the extension in phpinfo() calls.
 */
PHP_MINFO_FUNCTION(security_guard)
{
	php_info_print_table_start();
	php_info_print_table_header(2, "security_guard support", "enabled");
	php_info_print_table_row(2, "Version", SECURITY_GUARD_VERSION);
	php_info_print_table_row(2, "Enforcement mode", SG_G(enforcement_mode_str) ? SG_G(enforcement_mode_str) : "block");
	php_info_print_table_row(2, "Log scope", SG_G(log_scope_str) ? SG_G(log_scope_str) : "per_user");
	php_info_print_table_row(2, "Log format", SG_G(log_format_str) ? SG_G(log_format_str) : "jsonl");
	php_info_print_table_end();

	DISPLAY_INI_ENTRIES();
}

/* ---- Module entry ---- */

static const zend_function_entry security_guard_functions[] = {
	PHP_FE_END
};

zend_module_entry security_guard_module_entry = {
	STANDARD_MODULE_HEADER,
	SECURITY_GUARD_EXTNAME,
	security_guard_functions,
	PHP_MINIT(security_guard),
	PHP_MSHUTDOWN(security_guard),
	PHP_RINIT(security_guard),
	PHP_RSHUTDOWN(security_guard),
	PHP_MINFO(security_guard),
	SECURITY_GUARD_VERSION,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SECURITY_GUARD
#ifdef ZTS
ZEND_TSRMLS_CACHE_DEFINE()
#endif
ZEND_GET_MODULE(security_guard)
#endif
