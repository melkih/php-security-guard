/**
 * Main Header for security_guard
 *
 * Defines the core data structures, globals, and constants used across the extension.
 * Includes definitions for configuration storage and security decisions.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SECURITY_GUARD_H
#define SECURITY_GUARD_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_ini.h"
#include "ext/standard/info.h"
#include "zend_extensions.h"
#include "zend_execute.h"
#include "zend_hash.h"

#define SECURITY_GUARD_VERSION "0.3.0"
#define SECURITY_GUARD_EXTNAME "security_guard"

/* Enforcement modes */
#define SG_MODE_OFF     0
#define SG_MODE_MONITOR 1
#define SG_MODE_BLOCK   2

/* Log scopes */
#define SG_LOG_SCOPE_GLOBAL   0
#define SG_LOG_SCOPE_PER_USER 1

/* Log formats */
#define SG_LOG_FORMAT_JSONL 0
#define SG_LOG_FORMAT_PLAIN 1

/* Function groups */
#define SG_GROUP_COMMAND 1
#define SG_GROUP_FILE    2
#define SG_GROUP_NETWORK 3
#define SG_GROUP_CURL    4  /* internal: curl tracking helpers */

/* Decision reasons */
#define SG_REASON_ALLOWED                    "allowed"
#define SG_REASON_COMMAND_NOT_WHITELISTED    "command_not_whitelisted"
#define SG_REASON_DANGEROUS_OPERATOR         "dangerous_operator"
#define SG_REASON_FILE_NOT_WHITELISTED       "file_not_whitelisted"
#define SG_REASON_PATH_TRAVERSAL             "path_traversal"
#define SG_REASON_RELATIVE_PATH              "relative_path"
#define SG_REASON_SYMLINK_ESCAPE             "symlink_escape"
#define SG_REASON_DOMAIN_NOT_WHITELISTED     "domain_not_whitelisted"
#define SG_REASON_IP_NOT_WHITELISTED         "ip_not_whitelisted"
#define SG_REASON_PRIVATE_IP_BLOCKED         "private_ip_blocked"
#define SG_REASON_METADATA_ENDPOINT_BLOCKED  "metadata_endpoint_blocked"
#define SG_REASON_URL_NOT_WHITELISTED        "url_not_whitelisted"
#define SG_REASON_WILDCARD_NO_BASE_DOMAIN    "wildcard_no_base_domain"
#define SG_REASON_NO_URL_TRACKED             "no_url_tracked_for_handle"

/* Parsed network entry types */
#define SG_NET_TYPE_DOMAIN  1
#define SG_NET_TYPE_URL     2
#define SG_NET_TYPE_IP      3
#define SG_NET_TYPE_CIDR    4

/* Host type for logging */
#define SG_HOST_TYPE_DOMAIN  "domain"
#define SG_HOST_TYPE_IP      "ip"
#define SG_HOST_TYPE_UNKNOWN "unknown"

/* Max config line length */
#define SG_MAX_LINE_LEN  4096
#define SG_MAX_PATH_LEN  2048
#define SG_MAX_URL_LEN   2048

/* Private network CIDRs (checked when host is an explicit IP) */
/**
 * Represents a CIDR network range (IPv4).
 */
typedef struct _sg_cidr {
	uint32_t network;
	uint32_t mask;
} sg_cidr_t;

/* Parsed config entry (command/file/network) */
/**
 * Represents a single whitelist entry (command, file, or network target).
 */
typedef struct _sg_entry {
	char *value;          /**< Normalized value for matching */
	char *raw;            /**< Original value from configuration file */
	int   net_type;       /**< SG_NET_TYPE_* for network entries */
	uint32_t cidr_network; /**< Pre-parsed network for IPv4 CIDR */
	uint32_t cidr_mask;    /**< Pre-parsed mask for IPv4 CIDR */
	int is_ipv6;          /**< Flag for IPv6 entries */
} sg_entry_t;

/* Config state (loaded in MINIT, reloaded periodically) */
/**
 * Holds the complete security configuration, including all whitelists.
 */
typedef struct _sg_config {
	HashTable *commands;   /**< Map of allowed command binaries */
	HashTable *files;      /**< Map of allowed file paths/prefixes */
	HashTable *network;    /**< Map of allowed network targets */
	time_t commands_mtime; /**< Modification time of the commands file */
	time_t files_mtime;    /**< Modification time of the files file */
	time_t network_mtime;  /**< Modification time of the network file */
	time_t last_checked;   /**< Last time the files were checked for updates */
} sg_config_t;

/* Decision result */
/**
 * Detailed result of a security evaluation for a single function call.
 */
typedef struct _sg_decision {
	int     allowed;        /**< 1 if allowed, 0 if blocked */
	int     group;          /**< SG_GROUP_* category */
	char   *function_name;  /**< PHP function name being called */
	char   *target;         /**< Raw argument value being validated */
	char   *realpath_val;   /**< Resolved absolute path for files */
	char   *reason;         /**< Machine-readable reason code */
	char   *scheme;         /**< URL scheme (for network) */
	char   *host;           /**< Hostname or IP (for network) */
	int     port;           /**< Port number (for network) */
	char   *host_type;      /**< 'domain', 'ip', or 'unknown' */
	char   *rule_matched;   /**< The specific whitelist rule that allowed the call */
	char   *command_binary; /**< Extracted binary path (for commands) */
	char   *command_args;   /**< Extracted command arguments (for commands) */
} sg_decision_t;

/* Per-request curl handle tracking */
typedef struct _sg_curl_handle {
	char *url;   /* URL set via curl_setopt CURLOPT_URL */
} sg_curl_handle_t;

/* Module globals */
ZEND_BEGIN_MODULE_GLOBALS(security_guard)
	/* INI values */
	zend_bool enabled;
	char     *enforcement_mode_str;
	int       enforcement_mode;        /* SG_MODE_* */

	char     *allowed_commands_file;
	char     *allowed_files_file;
	char     *allowed_network_file;

	zend_bool log_allowed;
	zend_bool log_denied;
	char     *log_scope_str;
	int       log_scope;               /* SG_LOG_SCOPE_* */
	char     *log_path;
	char     *log_format_str;
	int       log_format;              /* SG_LOG_FORMAT_* */

	zend_bool allow_wildcard_domains;
	zend_bool require_base_domain_for_wildcard;
	zend_bool block_private_networks;
	zend_bool explicit_allow_overrides_private_block;
	zend_bool block_metadata_endpoints;
	zend_bool emit_php_warning;
	char     *block_message;

	zend_long config_reload_interval;
	zend_long log_target_max_length;
	zend_bool log_backtrace;
	zend_long log_rate_limit;

	/* Runtime state */
	sg_config_t *config;
	HashTable   *curl_handles;   /* zval resource -> sg_curl_handle_t* */
	char        *current_user;   /* effective Linux user for this request */
	int          current_uid;
	long         log_rate_count; /* rate limit counter per request */
ZEND_END_MODULE_GLOBALS(security_guard)

ZEND_EXTERN_MODULE_GLOBALS(security_guard)

#ifdef ZTS
#define SG_G(v) TSRMG(security_guard_globals_id, zend_security_guard_globals *, v)
#else
#define SG_G(v) (security_guard_globals.v)
#endif

extern zend_module_entry security_guard_module_entry;
#define phpext_security_guard_ptr &security_guard_module_entry

PHP_MINIT_FUNCTION(security_guard);
PHP_MSHUTDOWN_FUNCTION(security_guard);
PHP_RINIT_FUNCTION(security_guard);
PHP_RSHUTDOWN_FUNCTION(security_guard);
PHP_MINFO_FUNCTION(security_guard);

#endif /* SECURITY_GUARD_H */
