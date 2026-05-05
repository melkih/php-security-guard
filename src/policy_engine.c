/**
 * Policy Engine Implementation for security_guard
 *
 * Orchestrates the evaluation of PHP function calls against defined security policies.
 * Routes calls to specific policy handlers (command, file, or network).
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#include "policy_engine.h"
#include "command_policy.h"
#include "file_policy.h"
#include "network_policy.h"
#include "utils.h"
#include <string.h>

/* Static hash table of monitored function names → group */
typedef struct { const char *name; int group; } sg_monitored_fn_t;

static const sg_monitored_fn_t sg_monitored[] = {
	/* Command group */
	{ "exec",                 SG_GROUP_COMMAND },
	{ "passthru",             SG_GROUP_COMMAND },
	{ "shell_exec",           SG_GROUP_COMMAND },
	{ "system",               SG_GROUP_COMMAND },
	{ "proc_open",            SG_GROUP_COMMAND },
	{ "popen",                SG_GROUP_COMMAND },
	/* File group (may overlap with network if URL given) */
	{ "parse_ini_file",       SG_GROUP_FILE    },
	{ "show_source",          SG_GROUP_FILE    },
	{ "highlight_file",       SG_GROUP_FILE    },
	{ "readfile",             SG_GROUP_FILE    },
	/* Dual: file_get_contents / fopen dispatch based on arg */
	{ "file_get_contents",    SG_GROUP_FILE    },
	{ "fopen",                SG_GROUP_FILE    },
	/* Network group */
	{ "curl_exec",            SG_GROUP_NETWORK },
	{ "curl_multi_exec",      SG_GROUP_NETWORK },
	{ "fsockopen",            SG_GROUP_NETWORK },
	{ "pfsockopen",           SG_GROUP_NETWORK },
	{ "stream_socket_client", SG_GROUP_NETWORK },
	/* curl tracking helpers — intercepted but never blocked here */
	{ "curl_init",            SG_GROUP_CURL    },
	{ "curl_setopt",          SG_GROUP_CURL    },
	{ "curl_setopt_array",    SG_GROUP_CURL    },
	{ "curl_close",           SG_GROUP_CURL    },
	{ NULL, 0 }
};

/* Loaded once at MINIT into a HashTable for O(1) lookup */
static HashTable *sg_monitored_ht = NULL;

/**
 * Initializes the policy engine by populating the monitored functions hash table.
 * Called during MINIT.
 */
void sg_policy_engine_init(void)
{
	if (sg_monitored_ht) return;
	ALLOC_HASHTABLE(sg_monitored_ht);
	zend_hash_init(sg_monitored_ht, 32, NULL, NULL, 1); /* persistent */
	for (int i = 0; sg_monitored[i].name; i++) {
		zend_long group = sg_monitored[i].group;
		zend_hash_str_add_mem(sg_monitored_ht,
			sg_monitored[i].name, strlen(sg_monitored[i].name),
			&group, sizeof(zend_long));
	}
}

/**
 * Shuts down the policy engine and frees the monitored functions hash table.
 * Called during MSHUTDOWN.
 */
void sg_policy_engine_shutdown(void)
{
	if (sg_monitored_ht) {
		zend_hash_destroy(sg_monitored_ht);
		FREE_HASHTABLE(sg_monitored_ht);
		sg_monitored_ht = NULL;
	}
}

/**
 * Checks if a PHP function name is being monitored by the engine.
 *
 * @param fname Function name to check.
 * @return int 1 if monitored, 0 otherwise.
 */
int sg_is_monitored_function(const char *fname)
{
	if (!fname || !sg_monitored_ht) return 0;
	return zend_hash_str_find(sg_monitored_ht, fname, strlen(fname)) != NULL;
}

/**
 * Retrieves the function group (command, file, network, etc.) for a given function name.
 *
 * @param fname The PHP function name.
 * @return int The SG_GROUP_* constant, or 0 if not monitored.
 */
static int sg_get_function_group(const char *fname)
{
	if (!fname || !sg_monitored_ht) return 0;
	zend_long *grp = zend_hash_str_find_ptr(sg_monitored_ht, fname, strlen(fname));
	return grp ? (int)*grp : 0;
}

/**
 * Checks if the first argument of the current function call is a URL.
 * Used to route generic file functions (like file_get_contents) to the network policy group.
 *
 * @param execute_data Zend execution data.
 * @return int 1 if the argument is a URL, 0 otherwise.
 */
static int sg_is_url_arg(zend_execute_data *execute_data)
{
	uint32_t argc = ZEND_CALL_NUM_ARGS(execute_data);
	if (argc < 1) return 0;
	zval *arg = ZEND_CALL_ARG(execute_data, 1);
	if (!arg || Z_TYPE_P(arg) != IS_STRING) return 0;
	const char *s = Z_STRVAL_P(arg);
	return sg_str_has_prefix(s, "http://")  ||
	       sg_str_has_prefix(s, "https://") ||
	       sg_str_has_prefix(s, "ftp://")   ||
	       sg_str_has_prefix(s, "ftps://")  ||
	       sg_str_has_prefix(s, "tcp://")   ||
	       sg_str_has_prefix(s, "ssl://");
}

/**
 * Evaluates a monitored PHP function call and returns a security decision.
 *
 * @param fname Function name being called.
 * @param execute_data Zend execution data for the call.
 * @return sg_decision_t* Pointer to the decision structure, or NULL if no action needed.
 */
sg_decision_t *sg_evaluate_call(const char *fname, zend_execute_data *execute_data)
{
	int group = sg_get_function_group(fname);

	/* curl tracking helpers: update state, no policy decision */
	if (group == SG_GROUP_CURL) return NULL;

	/* file_get_contents / fopen: route by arg content */
	if (group == SG_GROUP_FILE && sg_is_url_arg(execute_data)) {
		group = SG_GROUP_NETWORK;
	}

	switch (group) {
		case SG_GROUP_COMMAND:
			return sg_command_evaluate(fname, execute_data);
		case SG_GROUP_FILE:
			return sg_file_evaluate(fname, execute_data);
		case SG_GROUP_NETWORK:
			return sg_network_evaluate(fname, execute_data);
		default:
			return NULL;
	}
}

/* Set the appropriate return value for a blocked function */
/**
 * Blocks the current PHP function call and sets a failure return value.
 * Optionally emits a PHP warning.
 *
 * @param fname Function name being blocked.
 * @param execute_data Zend execution data.
 * @param dec Security decision containing the block reason.
 */
void sg_block_call(const char *fname, zend_execute_data *execute_data,
                   sg_decision_t *dec)
{
	zval *retval = execute_data->return_value;
	if (!retval) return;

	/* shell_exec returns NULL on failure */
	if (strcmp(fname, "shell_exec") == 0) {
		ZVAL_NULL(retval);
	} else {
		ZVAL_FALSE(retval);
	}

	if (SG_G(emit_php_warning)) {
		const char *msg = SG_G(block_message);
		if (!msg || !*msg) msg = "Security policy blocked this operation";
		php_error_docref(NULL, E_WARNING,
			"security_guard: %s (%s)", msg,
			dec->reason ? dec->reason : "");
	}
}
