/**
 * Network Access Policy for security_guard
 *
 * Validates PHP functions that perform network operations (cURL, streams, sockets).
 * Implements domain whitelisting (including wildcards), IP/CIDR validation,
 * and blocks access to private networks and cloud metadata endpoints.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#include "network_policy.h"
#include "php_hooks.h"
#include "utils.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

/**
 * Checks if a hostname matches a domain entry (supports wildcards).
 *
 * @param host The hostname to check.
 * @param entry_value The whitelist entry to match against (e.g., 'example.com' or '*.example.com').
 * @return int 1 if matched, 0 otherwise.
 */
static int sg_domain_matches(const char *host, const char *entry_value)
{
	if (!host || !entry_value) return 0;

	/* Exact match */
	if (strcasecmp(host, entry_value) == 0) return 1;

	/* Wildcard: entry_value = *.foo.com */
	if (strncmp(entry_value, "*.", 2) == 0) {
		const char *base = entry_value + 2;
		/* host must end with .base and have exactly one extra label */
		size_t hlen = strlen(host);
		size_t blen = strlen(base);
		if (hlen <= blen + 1) return 0;  /* need at least x.base */
		if (host[hlen - blen - 1] != '.') return 0;
		if (strcasecmp(host + hlen - blen, base) != 0) return 0;
		/* Ensure no further dots in the subdomain label (single level) */
		size_t prefix_len = hlen - blen - 1;
		for (size_t i = 0; i < prefix_len; i++) {
			if (host[i] == '.') return 0;
		}
		return 1;
	}

	return 0;
}

/**
 * Checks if a parsed URL exactly matches a URL whitelist entry.
 * Validates scheme, host, port, and path.
 *
 * @param purl The parsed target URL.
 * @param entry_url The raw URL string from the whitelist.
 * @return int 1 if matched, 0 otherwise.
 */
static int sg_url_exact_matches(const sg_parsed_url_t *purl, const char *entry_url)
{
	if (!purl || !entry_url) return 0;
	sg_parsed_url_t ep;
	if (!sg_parse_url(entry_url, &ep)) return 0;
	if (strcasecmp(purl->scheme, ep.scheme) != 0) return 0;
	if (strcasecmp(purl->host, ep.host) != 0) return 0;
	if (purl->port != ep.port) return 0;
	if (strcmp(purl->path, ep.path) != 0) return 0;
	return 1;
}

/**
 * Core validation logic for a network URL/target.
 *
 * @param purl Parsed URL structure.
 * @param reason_out Pointer to store the reason string if denied.
 * @param rule_out Pointer to store the matching rule string if allowed.
 * @param host_type_out Pointer to store the host type (IP or Domain).
 * @return int 1 if allowed, 0 otherwise.
 */
int sg_network_url_allowed(const sg_parsed_url_t *purl, char **reason_out,
                            char **rule_out, char **host_type_out)
{
	sg_config_t *cfg = SG_G(config);
	if (!cfg) {
		if (reason_out)    *reason_out    = SG_REASON_DOMAIN_NOT_WHITELISTED;
		if (host_type_out) *host_type_out = SG_HOST_TYPE_UNKNOWN;
		return 0;
	}

	/* Metadata endpoint check (always, before whitelist) */
	if (SG_G(block_metadata_endpoints) && sg_is_metadata_host(purl->host)) {
		if (reason_out)    *reason_out    = SG_REASON_METADATA_ENDPOINT_BLOCKED;
		if (host_type_out) *host_type_out = purl->host_is_ip ? SG_HOST_TYPE_IP : SG_HOST_TYPE_DOMAIN;
		return 0;
	}

	if (purl->host_is_ip) {
		if (host_type_out) *host_type_out = SG_HOST_TYPE_IP;

		/* Private network block */
		if (SG_G(block_private_networks) && sg_ip_is_private(purl->host)) {
			if (!SG_G(explicit_allow_overrides_private_block)) {
				if (reason_out) *reason_out = SG_REASON_PRIVATE_IP_BLOCKED;
				return 0;
			}
			/* Check explicit whitelist before blocking */
			/* (fall through to normal IP check below) */
		}

		uint32_t ip32 = sg_ipv4_to_uint32(purl->host);

		/* Check ip entries */
		sg_entry_t *entry;
		ZEND_HASH_FOREACH_PTR(cfg->network, entry) {
			if (!entry) continue;
			if (entry->net_type == SG_NET_TYPE_IP) {
				if (strcasecmp(entry->value, purl->host) == 0) {
					if (rule_out) *rule_out = estrdup(entry->value);
					return 1;
				}
			} else if (entry->net_type == SG_NET_TYPE_CIDR && !entry->is_ipv6) {
				if (sg_ipv4_in_cidr(ip32, entry->cidr_network, entry->cidr_mask)) {
					if (rule_out) *rule_out = estrdup(entry->raw);
					return 1;
				}
			} else if (entry->net_type == SG_NET_TYPE_URL) {
				if (sg_url_exact_matches(purl, entry->raw)) {
					if (rule_out) *rule_out = estrdup(entry->raw);
					return 1;
				}
			}
		} ZEND_HASH_FOREACH_END();

		/* After explicit whitelist check failed, apply private block */
		if (SG_G(block_private_networks) && sg_ip_is_private(purl->host)) {
			if (reason_out) *reason_out = SG_REASON_PRIVATE_IP_BLOCKED;
			return 0;
		}

		if (reason_out) *reason_out = SG_REASON_IP_NOT_WHITELISTED;
		return 0;

	} else {
		/* Domain-based host */
		if (host_type_out) *host_type_out = SG_HOST_TYPE_DOMAIN;

		sg_entry_t *entry;
		ZEND_HASH_FOREACH_PTR(cfg->network, entry) {
			if (!entry) continue;
			if (entry->net_type == SG_NET_TYPE_DOMAIN) {
				if (!SG_G(allow_wildcard_domains) &&
				    strncmp(entry->value, "*.", 2) == 0) continue;
				if (sg_domain_matches(purl->host, entry->value)) {
					if (rule_out) *rule_out = estrdup(entry->value);
					return 1;
				}
			} else if (entry->net_type == SG_NET_TYPE_URL) {
				if (sg_url_exact_matches(purl, entry->raw)) {
					if (rule_out) *rule_out = estrdup(entry->raw);
					return 1;
				}
			}
		} ZEND_HASH_FOREACH_END();

		if (reason_out) *reason_out = SG_REASON_DOMAIN_NOT_WHITELISTED;
		return 0;
	}
}

/**
 * Evaluates a network call given a raw URL string.
 *
 * @param fname The PHP function name.
 * @param url The target URL string.
 * @return sg_decision_t* Pointer to the security decision.
 */
sg_decision_t *sg_network_evaluate_url(const char *fname, const char *url)
{
	sg_decision_t *dec = ecalloc(1, sizeof(sg_decision_t));
	dec->group         = SG_GROUP_NETWORK;
	dec->function_name = estrdup(fname);

	if (!url || !*url) {
		dec->allowed   = 0;
		dec->reason    = SG_REASON_NO_URL_TRACKED;
		dec->host_type = estrdup(SG_HOST_TYPE_UNKNOWN);
		return dec;
	}

	zend_long max_len = SG_G(log_target_max_length);
	if (max_len <= 0) max_len = 2048;
	dec->target = sg_strdup_truncate(url, (size_t)max_len);

	sg_parsed_url_t purl;
	if (!sg_parse_url(url, &purl)) {
		dec->allowed   = 0;
		dec->reason    = SG_REASON_DOMAIN_NOT_WHITELISTED;
		dec->host_type = estrdup(SG_HOST_TYPE_UNKNOWN);
		return dec;
	}

	dec->scheme = estrdup(purl.scheme);
	dec->host   = estrdup(purl.host);
	dec->port   = purl.port;

	char *reason    = NULL;
	char *rule      = NULL;
	char *host_type = NULL;

	int allowed = sg_network_url_allowed(&purl, &reason, &rule, &host_type);

	dec->allowed      = allowed;
	dec->reason       = reason ? reason : (allowed ? SG_REASON_ALLOWED : SG_REASON_DOMAIN_NOT_WHITELISTED);
	dec->rule_matched = rule;
	dec->host_type    = host_type ? estrdup(host_type) : estrdup(SG_HOST_TYPE_UNKNOWN);

	if (allowed && !dec->reason) dec->reason = SG_REASON_ALLOWED;

	return dec;
}

/**
 * High-level network call evaluator that routes specific functions (curl, fsockopen, etc.)
 * to the appropriate URL parsing and validation logic.
 *
 * @param fname The PHP function name.
 * @param execute_data Zend execution data.
 * @return sg_decision_t* Pointer to the security decision.
 */
sg_decision_t *sg_network_evaluate(const char *fname, zend_execute_data *execute_data)
{
	/* curl_exec / curl_multi_exec: URL tracked via handle */
	if (strcmp(fname, "curl_exec") == 0 || strcmp(fname, "curl_multi_exec") == 0) {
		uint32_t arg_count = ZEND_CALL_NUM_ARGS(execute_data);
		if (arg_count < 1) {
			sg_decision_t *dec = ecalloc(1, sizeof(sg_decision_t));
			dec->group         = SG_GROUP_NETWORK;
			dec->function_name = estrdup(fname);
			dec->allowed       = 0;
			dec->reason        = SG_REASON_NO_URL_TRACKED;
			dec->host_type     = estrdup(SG_HOST_TYPE_UNKNOWN);
			return dec;
		}
		zval *handle = ZEND_CALL_ARG(execute_data, 1);
		const char *url = sg_curl_get_url(handle);
		return sg_network_evaluate_url(fname, url);
	}

	/* fsockopen / pfsockopen: arg1=hostname, arg2=port */
	if (strcmp(fname, "fsockopen") == 0 || strcmp(fname, "pfsockopen") == 0) {
		uint32_t arg_count = ZEND_CALL_NUM_ARGS(execute_data);
		if (arg_count < 1) {
			sg_decision_t *dec = ecalloc(1, sizeof(sg_decision_t));
			dec->group         = SG_GROUP_NETWORK;
			dec->function_name = estrdup(fname);
			dec->allowed       = 0;
			dec->reason        = SG_REASON_DOMAIN_NOT_WHITELISTED;
			dec->host_type     = estrdup(SG_HOST_TYPE_UNKNOWN);
			return dec;
		}
		zval *arg1 = ZEND_CALL_ARG(execute_data, 1);
		int port = 0;
		if (arg_count >= 2) {
			zval *arg2 = ZEND_CALL_ARG(execute_data, 2);
			if (arg2 && Z_TYPE_P(arg2) == IS_LONG) port = (int)Z_LVAL_P(arg2);
		}
		const char *host = (arg1 && Z_TYPE_P(arg1) == IS_STRING) ? Z_STRVAL_P(arg1) : NULL;

		/* Build synthetic URL for validation */
		char synthetic_url[SG_MAX_URL_LEN];
		snprintf(synthetic_url, sizeof(synthetic_url), "tcp://%s:%d/",
		         host ? host : "", port);
		return sg_network_evaluate_url(fname, synthetic_url);
	}

	/* stream_socket_client: arg1 = "tcp://host:port" or "ssl://host:port" etc. */
	if (strcmp(fname, "stream_socket_client") == 0) {
		uint32_t arg_count = ZEND_CALL_NUM_ARGS(execute_data);
		if (arg_count < 1) {
			sg_decision_t *dec = ecalloc(1, sizeof(sg_decision_t));
			dec->group         = SG_GROUP_NETWORK;
			dec->function_name = estrdup(fname);
			dec->allowed       = 0;
			dec->reason        = SG_REASON_DOMAIN_NOT_WHITELISTED;
			dec->host_type     = estrdup(SG_HOST_TYPE_UNKNOWN);
			return dec;
		}
		zval *arg1 = ZEND_CALL_ARG(execute_data, 1);
		const char *remote = (arg1 && Z_TYPE_P(arg1) == IS_STRING) ? Z_STRVAL_P(arg1) : NULL;
		return sg_network_evaluate_url(fname, remote ? remote : "");
	}

	/* file_get_contents / fopen with URL */
	uint32_t arg_count = ZEND_CALL_NUM_ARGS(execute_data);
	if (arg_count < 1) {
		sg_decision_t *dec = ecalloc(1, sizeof(sg_decision_t));
		dec->group         = SG_GROUP_NETWORK;
		dec->function_name = estrdup(fname);
		dec->allowed       = 0;
		dec->reason        = SG_REASON_DOMAIN_NOT_WHITELISTED;
		dec->host_type     = estrdup(SG_HOST_TYPE_UNKNOWN);
		return dec;
	}
	zval *arg1 = ZEND_CALL_ARG(execute_data, 1);
	const char *url = (arg1 && Z_TYPE_P(arg1) == IS_STRING) ? Z_STRVAL_P(arg1) : NULL;
	return sg_network_evaluate_url(fname, url ? url : "");
}
