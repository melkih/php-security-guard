/**
 * File Policy Header
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SG_FILE_POLICY_H
#define SG_FILE_POLICY_H

#include "security_guard.h"

/* Evaluate a file-group function call. Returns heap-allocated decision. */
sg_decision_t *sg_file_evaluate(const char *fname, zend_execute_data *execute_data);

/* Check if a resolved absolute path is whitelisted */
int sg_file_is_allowed(const char *path, char **matched_rule_out);

#endif /* SG_FILE_POLICY_H */
