/**
 * Command Execution Policy for security_guard
 *
 * Validates PHP functions that execute system commands (exec, system, etc.).
 * Checks against the allowed commands whitelist and prevents dangerous shell operators.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#include "command_policy.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>

/**
 * Checks if a binary path is present in the allowed commands whitelist.
 *
 * @param binary The absolute path to the binary.
 * @return int 1 if allowed, 0 otherwise.
 */
int sg_command_is_allowed(const char *binary)
{
	sg_config_t *cfg = SG_G(config);
	if (!cfg || !binary) return 0;
	return zend_hash_str_find(cfg->commands, binary, strlen(binary)) != NULL;
}

/**
 * Extracts the command string from execute_data for functions like exec/shell_exec/system/passthru.
 *
 * @param execute_data Zend execution data.
 * @return const char* Command string if available, otherwise NULL.
 */
static const char *sg_get_string_arg(zend_execute_data *execute_data)
{
	if (!execute_data) return NULL;
	uint32_t arg_count = ZEND_CALL_NUM_ARGS(execute_data);
	if (arg_count < 1) return NULL;

	zval *arg = ZEND_CALL_ARG(execute_data, 1);
	if (arg && Z_TYPE_P(arg) == IS_STRING) {
		return Z_STRVAL_P(arg);
	}
	return NULL;
}

/**
 * Evaluates a command execution call.
 * Parses the binary and arguments, and checks for dangerous operators.
 *
 * @param fname The PHP function name being called.
 * @param execute_data Zend execution data.
 * @return sg_decision_t* Pointer to the security decision.
 */
sg_decision_t *sg_command_evaluate(const char *fname, zend_execute_data *execute_data)
{
	sg_decision_t *dec = ecalloc(1, sizeof(sg_decision_t));
	dec->group         = SG_GROUP_COMMAND;
	dec->function_name = estrdup(fname);
	dec->host_type     = estrdup("unknown");

	/* proc_open / popen may receive array or string */
	int is_proc = (strcmp(fname, "proc_open") == 0 || strcmp(fname, "popen") == 0);

	const char *cmd_str = NULL;
	uint32_t arg_count  = ZEND_CALL_NUM_ARGS(execute_data);

	if (arg_count < 1) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_COMMAND_NOT_WHITELISTED;
		return dec;
	}

	zval *arg1 = ZEND_CALL_ARG(execute_data, 1);

	if (is_proc && arg1 && Z_TYPE_P(arg1) == IS_ARRAY) {
		/* array command: first element is the binary */
		zval *first = zend_hash_index_find(Z_ARRVAL_P(arg1), 0);
		if (first && Z_TYPE_P(first) == IS_STRING) {
			cmd_str = Z_STRVAL_P(first);
		}
	} else if (arg1 && Z_TYPE_P(arg1) == IS_STRING) {
		cmd_str = Z_STRVAL_P(arg1);
	}

	if (!cmd_str) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_COMMAND_NOT_WHITELISTED;
		return dec;
	}

	/* Limit target length for logging */
	zend_long max_len = SG_G(log_target_max_length);
	if (max_len <= 0) max_len = 2048;
	dec->target = sg_strdup_truncate(cmd_str, (size_t)max_len);

	/* Check dangerous operators first */
	if (!is_proc && sg_command_has_dangerous_operator(cmd_str)) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_DANGEROUS_OPERATOR;
		return dec;
	}

	/* Extract binary */
	char binary[SG_MAX_PATH_LEN];
	char args[SG_MAX_PATH_LEN];
	if (!sg_extract_binary(cmd_str, binary, sizeof(binary), args, sizeof(args))) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_COMMAND_NOT_WHITELISTED;
		return dec;
	}

	/* Must be absolute */
	if (!sg_is_absolute_path(binary)) {
		dec->allowed = 0;
		dec->reason  = SG_REASON_COMMAND_NOT_WHITELISTED;
		return dec;
	}

	dec->command_binary = estrdup(binary);
	dec->command_args   = estrdup(args);

	if (sg_command_is_allowed(binary)) {
		dec->allowed     = 1;
		dec->reason      = SG_REASON_ALLOWED;
		dec->rule_matched = estrdup(binary);
	} else {
		dec->allowed = 0;
		dec->reason  = SG_REASON_COMMAND_NOT_WHITELISTED;
	}

	return dec;
}
