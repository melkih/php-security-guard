/**
 * Config Loader Header
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#ifndef SG_CONFIG_LOADER_H
#define SG_CONFIG_LOADER_H

#include "security_guard.h"

sg_config_t *sg_config_load(void);
void         sg_config_free(sg_config_t *cfg);
void         sg_config_reload_if_needed(void);

/* Parse a single .conf file into the given HashTable.
   type_filter: "command", "file", "domain", "url", "ip", "cidr", or NULL for all. */
int sg_load_conf_file(const char *path, HashTable *ht, const char *type_filter,
                      time_t *mtime_out);

/* Normalize a network entry value for use as hash key */
char *sg_normalize_network_key(int net_type, const char *value);

/* Validate wildcard: *.foo.com requires foo.com to also be present */
int sg_validate_wildcards(HashTable *network_ht);

#endif /* SG_CONFIG_LOADER_H */
