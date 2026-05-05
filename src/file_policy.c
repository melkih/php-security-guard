/**
 * File Access Policy for security_guard
 *
 * Validates PHP functions that access the local filesystem.
 * Implements prefix-based whitelisting, absolute path enforcement,
 * and protection against path traversal and symlink escapes.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#include "file_policy.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>

/**
 * Checks if a filesystem path is allowed by the whitelist.
 * Supports exact matches and directory prefix matches.
 *
 * @param path The absolute path to check.
 * @param matched_rule_out Pointer to store the rule that matched (must be freed).
 * @return int 1 if allowed, 0 otherwise.
 */
int sg_file_is_allowed(const char *path, char **matched_rule_out)
{
	sg_config_t *cfg = SG_G(config);
	if (!cfg || !path) return 0;

	/* Exact match first */
	if (zend_hash_str_find(cfg->files, path, strlen(path)) != NULL) {
		if (matched_rule_out) *matched_rule_out = estrdup(path);
		return 1;
	}

	/* Check if path starts with any allowed directory prefix */
	sg_entry_t *entry;
	ZEND_HASH_FOREACH_PTR(cfg->files, entry) {
		if (!entry || !entry->value) continue;
		size_t elen = strlen(entry->value);

		/* Directory prefix match: allowed_path must be a prefix of path,
		   followed by '/' (or exact match already handled above) */
		if (strncmp(path, entry->value, elen) == 0) {
			char after = path[elen];
			if (after == '/' || after == '\0') {
				if (matched_rule_out) *matched_rule_out = estrdup(entry->value);
				return 1;
			}
		}
	} ZEND_HASH_FOREACH_END();

	return 0;
}

/**
 * Evaluates a file access call.
 * Performs normalization, symlink resolution, and security checks.
 *
 * @param fname The PHP function name being called.
 * @param execute_data Zend execution data.
 * @return sg_decision_t* Pointer to the security decision.
 */
sg_decision_t *sg_file_evaluate(const char *fname, zend_execute_data *execute_data)
{
	sg_decision_t *dec = ecalloc(1, sizeof(sg_decision_t));
	dec->group         = SG_GROUP_FILE;
	dec->function_name = estrdup(fname);
	dec->host_type     = estrdup("unknown");

	uint32_t arg_count = ZEND_CALL_NUM_ARGS(execute_data);
	if (arg_count < 1) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_FILE_NOT_WHITELISTED;
		return dec;
	}

	zval *arg1 = ZEND_CALL_ARG(execute_data, 1);
	if (!arg1 || Z_TYPE_P(arg1) != IS_STRING) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_FILE_NOT_WHITELISTED;
		return dec;
	}

	const char *raw_path = Z_STRVAL_P(arg1);
	zend_long max_len = SG_G(log_target_max_length);
	if (max_len <= 0) max_len = 2048;
	dec->target = sg_strdup_truncate(raw_path, (size_t)max_len);

	/* Detect URL-style paths (network group handled separately) */
	if (sg_str_has_prefix(raw_path, "http://") ||
	    sg_str_has_prefix(raw_path, "https://") ||
	    sg_str_has_prefix(raw_path, "ftp://") ||
	    sg_str_has_prefix(raw_path, "ftps://")) {
		/* Delegate to network policy — mark as not-file-group */
		dec->allowed = -1;  /* caller will re-route */
		dec->reason  = SG_REASON_FILE_NOT_WHITELISTED;
		return dec;
	}

	/* Must be absolute */
	if (!sg_is_absolute_path(raw_path)) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_RELATIVE_PATH;
		return dec;
	}

	/* Path traversal check on raw string */
	if (sg_has_path_traversal(raw_path)) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_PATH_TRAVERSAL;
		return dec;
	}

	/* Resolve symlinks */
	char *resolved = sg_resolve_realpath(raw_path);
	if (resolved) {
		dec->realpath_val = resolved;

		/* Symlink escape: if resolved path differs and resolved isn't allowed */
		if (strcmp(resolved, raw_path) != 0 && sg_has_path_traversal(resolved)) {
			dec->allowed = 0;
			dec->reason  = SG_REASON_SYMLINK_ESCAPE;
			return dec;
		}

		char *matched = NULL;
		if (sg_file_is_allowed(resolved, &matched)) {
			dec->allowed     = 1;
			dec->reason      = SG_REASON_ALLOWED;
			dec->rule_matched = matched;
			return dec;
		}
	}

	/* Fallback: check raw path */
	char *matched = NULL;
	if (sg_file_is_allowed(raw_path, &matched)) {
		dec->allowed     = 1;
		dec->reason      = SG_REASON_ALLOWED;
		dec->rule_matched = matched;
		return dec;
	}

	dec->allowed = 0;
	dec->reason  = SG_REASON_FILE_NOT_WHITELISTED;
	return dec;
}
