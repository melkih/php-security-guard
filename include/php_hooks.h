/**
 * PHP Hooks Header
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SG_PHP_HOOKS_H
#define SG_PHP_HOOKS_H

#include "security_guard.h"

/* Install / remove zend_execute_ex hook */
void sg_hooks_install(void);
void sg_hooks_uninstall(void);

/* The replacement execute handlers */
void sg_execute_ex(zend_execute_data *execute_data);
void sg_execute_internal(zend_execute_data *execute_data, zval *return_value);

/* curl handle tracking */
void sg_curl_track_init(zval *handle, const char *url);
void sg_curl_track_setopt(zval *handle, zend_long option, zval *value);
void sg_curl_track_setopt_array(zval *handle, HashTable *options);
const char *sg_curl_get_url(zval *handle);
void sg_curl_track_close(zval *handle);

/* Pointer to original handlers — restored on MSHUTDOWN */
extern void (*sg_original_execute_ex)(zend_execute_data *execute_data);
extern void (*sg_original_execute_internal)(zend_execute_data *execute_data, zval *return_value);

#endif /* SG_PHP_HOOKS_H */
