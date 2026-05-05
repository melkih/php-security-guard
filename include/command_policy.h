/**
 * Command Policy Header
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SG_COMMAND_POLICY_H
#define SG_COMMAND_POLICY_H

#include "security_guard.h"

/* Evaluate a command-group function call. Returns heap-allocated decision. */
sg_decision_t *sg_command_evaluate(const char *fname, zend_execute_data *execute_data);

/* Check if a binary path is whitelisted */
int sg_command_is_allowed(const char *binary);

#endif /* SG_COMMAND_POLICY_H */
