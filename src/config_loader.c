/**
 * Configuration Loader for security_guard
 *
 * Responsible for reading, parsing, and caching the whitelist configuration files.
 * Supports hot-reloading based on file modification time.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#include "config_loader.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>

/**
 * Parses a single line from a configuration file.
 * Expected format: type|value|date|user[|obs]
 *
 * @param line The raw line to parse.
 * @param type_out Buffer to store the parsed type.
 * @param type_len Size of the type buffer.
 * @param value_out Buffer to store the parsed value.
 * @param value_len Size of the value buffer.
 * @return int 1 on success, 0 to skip (invalid or comment).
 */
static int sg_parse_conf_line(const char *line, char *type_out, size_t type_len,
                               char *value_out, size_t value_len)
{
	if (!line || !type_out || !value_out) return 0;
	/* skip blank / comment */
	while (*line && (*line == ' ' || *line == '\t')) line++;
	if (!*line || *line == '#') return 0;

	/* type */
	const char *sep = strchr(line, '|');
	if (!sep) return 0;
	size_t tlen = (size_t)(sep - line);
	if (tlen == 0 || tlen >= type_len) return 0;
	memcpy(type_out, line, tlen);
	type_out[tlen] = '\0';

	/* value */
	const char *vstart = sep + 1;
	const char *vsep   = strchr(vstart, '|');
	size_t vlen = vsep ? (size_t)(vsep - vstart) : strlen(vstart);
	if (vlen == 0 || vlen >= value_len) return 0;
	memcpy(value_out, vstart, vlen);
	value_out[vlen] = '\0';
	return 1;
}

/**
 * Retrieves the modification time of a file.
 *
 * @param path The path to the file.
 * @return time_t The modification time, or 0 on failure.
 */
static time_t sg_file_mtime(const char *path)
{
	if (!path) return 0;
	struct stat st;
	if (stat(path, &st) != 0) return 0;
	return st.st_mtime;
}

/**
 * Inserts a network entry into the configuration HashTable.
 * Supports domains, URLs, IPs, and CIDR blocks. Handles deduplication.
 *
 * @param ht The destination HashTable.
 * @param type_str The type of network entry as a string.
 * @param value The value of the network entry.
 */
static void sg_insert_network_entry(HashTable *ht, const char *type_str,
                                    const char *value)
{
	int net_type;
	if (strcmp(type_str, "domain") == 0)      net_type = SG_NET_TYPE_DOMAIN;
	else if (strcmp(type_str, "url") == 0)    net_type = SG_NET_TYPE_URL;
	else if (strcmp(type_str, "ip") == 0)     net_type = SG_NET_TYPE_IP;
	else if (strcmp(type_str, "cidr") == 0)   net_type = SG_NET_TYPE_CIDR;
	else return;

	char *key = sg_normalize_network_key(net_type, value);
	if (!key) return;

	/* Dedup: skip if already present */
	if (zend_hash_str_find(ht, key, strlen(key)) != NULL) {
		pefree(key, 1);
		return;
	}

	sg_entry_t *entry = pecalloc(1, sizeof(sg_entry_t), 1);
	entry->value    = pestrdup(key, 1);
	entry->raw      = pestrdup(value, 1);
	entry->net_type = net_type;
	entry->is_ipv6  = 0;

	if (net_type == SG_NET_TYPE_CIDR) {
		if (strchr(value, ':')) {
			/* IPv6 CIDR — store raw, match by string comparison (basic) */
			entry->is_ipv6 = 1;
		} else {
			sg_parse_cidr(value, &entry->cidr_network, &entry->cidr_mask);
		}
	}

	zend_hash_str_add_ptr(ht, key, strlen(key), entry);
	pefree(key, 1);
}

/**
 * Inserts a simple entry (like command or file) into the configuration HashTable.
 *
 * @param ht The destination HashTable.
 * @param value The value to insert.
 */
static void sg_insert_simple_entry(HashTable *ht, const char *value)
{
	/* Dedup */
	if (zend_hash_str_find(ht, value, strlen(value)) != NULL) return;

	sg_entry_t *entry = pecalloc(1, sizeof(sg_entry_t), 1);
	entry->value = pestrdup(value, 1);
	entry->raw   = pestrdup(value, 1);

	zend_hash_str_add_ptr(ht, value, strlen(value), entry);
}

/**
 * Loads a configuration file into a HashTable.
 *
 * @param path Path to the .conf file.
 * @param ht Destination hash table.
 * @param type_filter Type of entries to load (e.g., 'command', 'file', 'network').
 * @param mtime_out Pointer to store the modification time of the loaded file.
 * @return int 1 on success, 0 on failure.
 */
int sg_load_conf_file(const char *path, HashTable *ht, const char *type_filter,
                      time_t *mtime_out)
{
	if (!path || !ht) return 0;

	if (mtime_out) *mtime_out = sg_file_mtime(path);

	FILE *fp = fopen(path, "r");
	if (!fp) return 0;

	char line[SG_MAX_LINE_LEN];
	char type_buf[64];
	char value_buf[SG_MAX_PATH_LEN];

	while (fgets(line, sizeof(line), fp)) {
		/* strip newline */
		size_t llen = strlen(line);
		while (llen > 0 && (line[llen-1] == '\n' || line[llen-1] == '\r')) {
			line[--llen] = '\0';
		}

		if (!sg_parse_conf_line(line, type_buf, sizeof(type_buf),
		                        value_buf, sizeof(value_buf))) {
			continue;
		}

		if (type_filter && strcmp(type_buf, type_filter) != 0) {
			/* For network file, accept all 4 types */
			if (strcmp(type_filter, "network") != 0) continue;
		}

		/* Commands: normalize to absolute path */
		if (strcmp(type_buf, "command") == 0) {
			if (value_buf[0] != '/') continue; /* must be absolute */
			sg_insert_simple_entry(ht, value_buf);
		}
		/* Files */
		else if (strcmp(type_buf, "file") == 0) {
			if (value_buf[0] != '/') continue;
			sg_insert_simple_entry(ht, value_buf);
		}
		/* Network types */
		else if (strcmp(type_buf, "domain") == 0 ||
		         strcmp(type_buf, "url") == 0 ||
		         strcmp(type_buf, "ip") == 0 ||
		         strcmp(type_buf, "cidr") == 0) {
			sg_insert_network_entry(ht, type_buf, value_buf);
		}
	}

	fclose(fp);
	return 1;
}

/**
 * Normalizes a network key based on its type for consistent hash table lookups.
 *
 * @param net_type The SG_NET_TYPE_ constant.
 * @param value The raw value to normalize.
 * @return char* Allocated string with the normalized key. Must be freed with efree().
 */
char *sg_normalize_network_key(int net_type, const char *value)
{
	if (!value) return NULL;
	char *key = pestrdup(value, 1);

	if (net_type == SG_NET_TYPE_DOMAIN) {
		/* lowercase + strip trailing dot */
		for (size_t i = 0; key[i]; i++) key[i] = (char)tolower((unsigned char)key[i]);
		sg_strip_trailing_dot(key);
	} else if (net_type == SG_NET_TYPE_IP) {
		/* canonical form: store as-is (inet_pton validates externally) */
	} else if (net_type == SG_NET_TYPE_URL) {
		/* lowercase scheme+host part */
		for (size_t i = 0; key[i]; i++) key[i] = (char)tolower((unsigned char)key[i]);
	} else if (net_type == SG_NET_TYPE_CIDR) {
		/* lowercase for IPv6, keep IPv4 as-is */
		for (size_t i = 0; key[i]; i++) key[i] = (char)tolower((unsigned char)key[i]);
	}

	return key;
}

/* Validate wildcards: every *.foo.com needs foo.com to exist */
/**
 * Validates that wildcard domains have their base domain explicitly allowed.
 *
 * @param network_ht Hash table containing network entries.
 * @return int 1 if all wildcards are valid, 0 otherwise.
 */
int sg_validate_wildcards(HashTable *network_ht)
{
	if (!SG_G(require_base_domain_for_wildcard)) return 1;

	int valid = 1;
	sg_entry_t *entry;
	ZEND_HASH_FOREACH_PTR(network_ht, entry) {
		if (!entry || entry->net_type != SG_NET_TYPE_DOMAIN) continue;
		const char *v = entry->value;
		if (!v || strncmp(v, "*.", 2) != 0) continue;

		/* base domain is v+2 */
		const char *base = v + 2;
		if (zend_hash_str_find(network_ht, base, strlen(base)) == NULL) {
			php_error_docref(NULL, E_WARNING,
				"security_guard: wildcard '%s' has no base domain '%s' in allowed_network",
				v, base);
			valid = 0;
		}
	} ZEND_HASH_FOREACH_END();

	return valid;
}

/**
 * Destructor callback for the configuration HashTables.
 * Frees the associated sg_entry_t structures.
 *
 * @param zv Pointer to the zval containing the sg_entry_t.
 */
static void sg_free_entry_ht(zval *zv)
{
	sg_entry_t *entry = (sg_entry_t *)Z_PTR_P(zv);
	if (entry) sg_entry_free(entry);
}

/**
 * Loads the complete security configuration from all configured files.
 *
 * @return sg_config_t* Pointer to the newly allocated configuration structure.
 */
sg_config_t *sg_config_load(void)
{
	sg_config_t *cfg = pecalloc(1, sizeof(sg_config_t), 1);

	cfg->commands = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(cfg->commands, 64, NULL, sg_free_entry_ht, 1);

	cfg->files = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(cfg->files, 64, NULL, sg_free_entry_ht, 1);

	cfg->network = pemalloc(sizeof(HashTable), 1);
	zend_hash_init(cfg->network, 128, NULL, sg_free_entry_ht, 1);

	const char *cmd_file = SG_G(allowed_commands_file);
	const char *fil_file = SG_G(allowed_files_file);
	const char *net_file = SG_G(allowed_network_file);

	if (cmd_file && *cmd_file) {
		sg_load_conf_file(cmd_file, cfg->commands, "command", &cfg->commands_mtime);
	}
	if (fil_file && *fil_file) {
		sg_load_conf_file(fil_file, cfg->files, "file", &cfg->files_mtime);
	}
	if (net_file && *net_file) {
		sg_load_conf_file(net_file, cfg->network, "network", &cfg->network_mtime);
		sg_validate_wildcards(cfg->network);
	}

	cfg->last_checked = time(NULL);
	return cfg;
}

/**
 * Frees a security configuration structure and all its associated memory.
 *
 * @param cfg Pointer to the configuration to free.
 */
void sg_config_free(sg_config_t *cfg)
{
	if (!cfg) return;
	if (cfg->commands) {
		zend_hash_destroy(cfg->commands);
		pefree(cfg->commands, 1);
	}
	if (cfg->files) {
		zend_hash_destroy(cfg->files);
		pefree(cfg->files, 1);
	}
	if (cfg->network) {
		zend_hash_destroy(cfg->network);
		pefree(cfg->network, 1);
	}
	pefree(cfg, 1);
}

/**
 * Checks if any configuration files have changed and reloads them if necessary.
 * The check is performed according to the 'config_reload_interval' INI setting.
 */
void sg_config_reload_if_needed(void)
{
	sg_config_t *cfg = SG_G(config);
	if (!cfg) {
		SG_G(config) = sg_config_load();
		return;
	}

	zend_long interval = SG_G(config_reload_interval);
	if (interval <= 0) return;

	time_t now = time(NULL);
	if ((now - cfg->last_checked) < interval) return;

	cfg->last_checked = now;

	int needs_reload = 0;
	const char *cmd_file = SG_G(allowed_commands_file);
	const char *fil_file = SG_G(allowed_files_file);
	const char *net_file = SG_G(allowed_network_file);

	if (cmd_file && *cmd_file && sg_file_mtime(cmd_file) != cfg->commands_mtime) needs_reload = 1;
	if (fil_file && *fil_file && sg_file_mtime(fil_file) != cfg->files_mtime)    needs_reload = 1;
	if (net_file && *net_file && sg_file_mtime(net_file) != cfg->network_mtime)  needs_reload = 1;

	if (needs_reload) {
		sg_config_t *new_cfg = sg_config_load();
		sg_config_free(cfg);
		SG_G(config) = new_cfg;
	}
}
