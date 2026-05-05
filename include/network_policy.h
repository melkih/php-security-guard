/**
 * Network Policy Header
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SG_NETWORK_POLICY_H
#define SG_NETWORK_POLICY_H

#include "security_guard.h"

/* Evaluate a network-group function call. Returns heap-allocated decision. */
sg_decision_t *sg_network_evaluate(const char *fname, zend_execute_data *execute_data);

/* Evaluate a URL/target string directly (used by curl tracking) */
sg_decision_t *sg_network_evaluate_url(const char *fname, const char *url);

/* Check if a parsed URL is allowed by the network policy */
int sg_network_url_allowed(const sg_parsed_url_t *purl, char **reason_out,
                            char **rule_out, char **host_type_out);

#endif /* SG_NETWORK_POLICY_H */
