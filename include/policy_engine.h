/**
 * Policy Engine Header
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SG_POLICY_ENGINE_H
#define SG_POLICY_ENGINE_H

#include "security_guard.h"

/* Lifecycle — called from MINIT / MSHUTDOWN */
void sg_policy_engine_init(void);
void sg_policy_engine_shutdown(void);

/* Evaluate a monitored function call and fill decision. */
sg_decision_t *sg_evaluate_call(const char *fname, zend_execute_data *execute_data);

/* Check if fname is in the monitored set (fast hash lookup) */
int sg_is_monitored_function(const char *fname);

/* Block a function call: set return value, optionally emit warning */
void sg_block_call(const char *fname, zend_execute_data *execute_data,
                   sg_decision_t *dec);

#endif /* SG_POLICY_ENGINE_H */
