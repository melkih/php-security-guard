/**
 * Utility Header for security_guard
 *
 * Prototypes for string, network, and system utility functions.
 * Also defines the structure for parsed URLs.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SG_UTILS_H
#define SG_UTILS_H

#include "security_guard.h"
#include <stdint.h>
#include <sys/types.h>

/* String helpers */
char *sg_strtolower_dup(const char *s);
char *sg_strdup_truncate(const char *s, size_t max_len);
void  sg_strip_trailing_dot(char *domain);
int   sg_str_has_prefix(const char *s, const char *prefix);
int   sg_str_has_suffix(const char *s, const char *suffix);

/* URL parsing */
/**
 * Represents a parsed URL for security evaluation.
 */
typedef struct _sg_parsed_url {
	char scheme[32];   /**< Protocol scheme (e.g., 'http', 'tcp') */
	char host[512];    /**< Hostname or IP address */
	char path[2048];   /**< Resource path */
	int  port;         /**< Port number */
	int  host_is_ip;   /**< 1 if host is an IP address */
	int  host_is_ipv6; /**< 1 if host is an IPv6 address */
} sg_parsed_url_t;

int sg_parse_url(const char *url, sg_parsed_url_t *out);

/* IP helpers */
int      sg_is_ipv4(const char *s);
int      sg_is_ipv6(const char *s);
uint32_t sg_ipv4_to_uint32(const char *ip);
int      sg_ipv4_in_cidr(uint32_t ip, uint32_t network, uint32_t mask);
int      sg_parse_cidr(const char *cidr, uint32_t *network_out, uint32_t *mask_out);
int      sg_ip_is_private(const char *ip);
int      sg_is_metadata_host(const char *host);

/* Command helpers */
int  sg_command_has_dangerous_operator(const char *cmd);
int  sg_extract_binary(const char *cmd, char *binary_out, size_t binary_len,
                       char *args_out, size_t args_len);

/* File path helpers */
int  sg_is_absolute_path(const char *path);
int  sg_has_path_traversal(const char *path);
char *sg_resolve_realpath(const char *path);

/* Timestamp */
void sg_timestamp_now(char *buf, size_t len);

/* Effective user for current process */
void sg_get_effective_user(char *user_out, size_t user_len, int *uid_out);

/* Current PHP script path */
const char *sg_current_script(void);

/* JSON escaping */
void sg_json_escape(const char *in, char *out, size_t out_len);

/* Safe free wrappers */
void sg_entry_free(sg_entry_t *entry);
void sg_decision_free(sg_decision_t *dec);

#endif /* SG_UTILS_H */
