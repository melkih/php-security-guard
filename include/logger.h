/**
 * Logger Header
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SG_LOGGER_H
#define SG_LOGGER_H

#include "security_guard.h"

/* Write allow/deny log entry */
void sg_log_allow(sg_decision_t *dec);
void sg_log_deny(sg_decision_t *dec);
void sg_log_monitor_violation(sg_decision_t *dec);

/* Internal: resolve the log file path for the current user */
char *sg_log_file_path(void);

/* Rate limiting */
int sg_log_rate_check(void);

#endif /* SG_LOGGER_H */
