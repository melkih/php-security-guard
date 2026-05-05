/**
 * Utility Functions for security_guard
 *
 * Provides string manipulation, network parsing, IP validation,
 * and system-level utility functions.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#include "utils.h"
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <pwd.h>
#include <unistd.h>
#include <limits.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <time.h>

/**
 * Creates a duplicate of a string in lowercase.
 *
 * @param s String to duplicate.
 * @return char* Allocated lowercase string. Must be freed with efree().
 */
char *sg_strtolower_dup(const char *s)
{
	if (!s) return NULL;
	size_t len = strlen(s);
	char *out = emalloc(len + 1);
	for (size_t i = 0; i < len; i++) {
		out[i] = (char)tolower((unsigned char)s[i]);
	}
	out[len] = '\0';
	return out;
}

/**
 * Duplicates a string and truncates it to a maximum length.
 *
 * @param s String to duplicate.
 * @param max_len Maximum length of the output string.
 * @return char* Allocated string. Must be freed with efree().
 */
char *sg_strdup_truncate(const char *s, size_t max_len)
{
	if (!s) return NULL;
	size_t len = strlen(s);
	if (len > max_len) len = max_len;
	char *out = emalloc(len + 1);
	memcpy(out, s, len);
	out[len] = '\0';
	return out;
}

/**
 * Strips the trailing dot from a domain name string.
 * Modifies the string in place.
 *
 * @param domain Domain name string.
 */
void sg_strip_trailing_dot(char *domain)
{
	if (!domain) return;
	size_t len = strlen(domain);
	while (len > 0 && domain[len - 1] == '.') {
		domain[--len] = '\0';
	}
}

/**
 * Checks if a string starts with a specific prefix.
 *
 * @param s String to check.
 * @param prefix Prefix to search for.
 * @return int 1 if it has the prefix, 0 otherwise.
 */
int sg_str_has_prefix(const char *s, const char *prefix)
{
	return strncmp(s, prefix, strlen(prefix)) == 0;
}

/**
 * Checks if a string ends with a specific suffix.
 *
 * @param s String to check.
 * @param suffix Suffix to search for.
 * @return int 1 if it has the suffix, 0 otherwise.
 */
int sg_str_has_suffix(const char *s, const char *suffix)
{
	size_t slen = strlen(s);
	size_t plen = strlen(suffix);
	if (plen > slen) return 0;
	return strcmp(s + slen - plen, suffix) == 0;
}

/* Minimal URL parser — no malloc for allocation, writes into out.
   Handles: scheme://host[:port][/path] */
/**
 * Minimal URL parser for security policy checking.
 *
 * @param url URL to parse.
 * @param out Pointer to structure where parsed components will be stored.
 * @return int 1 on success, 0 on failure.
 */
int sg_parse_url(const char *url, sg_parsed_url_t *out)
{
	if (!url || !out) return 0;
	memset(out, 0, sizeof(*out));

	/* scheme */
	const char *p = strstr(url, "://");
	if (!p) return 0;
	size_t scheme_len = (size_t)(p - url);
	if (scheme_len >= sizeof(out->scheme)) return 0;
	memcpy(out->scheme, url, scheme_len);
	out->scheme[scheme_len] = '\0';
	for (size_t i = 0; i < scheme_len; i++) {
		out->scheme[i] = (char)tolower((unsigned char)out->scheme[i]);
	}

	p += 3; /* skip :// */

	/* default ports */
	if (strcmp(out->scheme, "https") == 0) out->port = 443;
	else if (strcmp(out->scheme, "http") == 0) out->port = 80;
	else if (strcmp(out->scheme, "ftp") == 0) out->port = 21;
	else out->port = 0;

	/* host */
	const char *host_start = p;

	/* IPv6 literal */
	int is_ipv6 = 0;
	if (*p == '[') {
		is_ipv6 = 1;
		const char *bracket_end = strchr(p, ']');
		if (!bracket_end) return 0;
		size_t hlen = (size_t)(bracket_end - p + 1);
		if (hlen >= sizeof(out->host)) return 0;
		memcpy(out->host, p, hlen);
		out->host[hlen] = '\0';
		out->host_is_ipv6 = 1;
		out->host_is_ip = 1;
		p = bracket_end + 1;
	} else {
		/* find end of host */
		const char *host_end = p;
		while (*host_end && *host_end != ':' && *host_end != '/' && *host_end != '?') {
			host_end++;
		}
		size_t hlen = (size_t)(host_end - p);
		if (hlen == 0 || hlen >= sizeof(out->host)) return 0;
		memcpy(out->host, p, hlen);
		out->host[hlen] = '\0';

		/* lowercase host */
		for (size_t i = 0; i < hlen; i++) {
			out->host[i] = (char)tolower((unsigned char)out->host[i]);
		}
		sg_strip_trailing_dot(out->host);

		out->host_is_ip = sg_is_ipv4(out->host);
		if (out->host_is_ip) out->host_is_ipv6 = 0;
		p = host_end;
	}

	/* port */
	if (*p == ':') {
		p++;
		char *endptr;
		long port = strtol(p, &endptr, 10);
		if (endptr > p && port > 0 && port <= 65535) {
			out->port = (int)port;
			p = endptr;
		}
	}

	/* path */
	if (*p == '/' || *p == '?' || *p == '#') {
		size_t path_len = strlen(p);
		if (path_len >= sizeof(out->path)) path_len = sizeof(out->path) - 1;
		memcpy(out->path, p, path_len);
		out->path[path_len] = '\0';
	} else {
		out->path[0] = '/';
		out->path[1] = '\0';
	}

	(void)host_start;
	(void)is_ipv6;
	return 1;
}

/**
 * Checks if a string is a valid IPv4 address.
 *
 * @param s String to check.
 * @return int 1 if valid IPv4, 0 otherwise.
 */
int sg_is_ipv4(const char *s)
{
	struct in_addr addr;
	return inet_pton(AF_INET, s, &addr) == 1;
}

/**
 * Checks if a string is a valid IPv6 address.
 *
 * @param s String to check.
 * @return int 1 if valid IPv6, 0 otherwise.
 */
int sg_is_ipv6(const char *s)
{
	/* Strip brackets if present */
	char buf[128];
	if (s[0] == '[') {
		size_t len = strlen(s);
		if (len < 3 || s[len - 1] != ']') return 0;
		len -= 2;
		if (len >= sizeof(buf)) return 0;
		memcpy(buf, s + 1, len);
		buf[len] = '\0';
		s = buf;
	}
	struct in6_addr addr;
	return inet_pton(AF_INET6, s, &addr) == 1;
}

/**
 * Converts an IPv4 address string to an unsigned 32-bit integer (host byte order).
 *
 * @param ip IPv4 string.
 * @return uint32_t Parsed integer or 0 on failure.
 */
uint32_t sg_ipv4_to_uint32(const char *ip)
{
	struct in_addr addr;
	if (inet_pton(AF_INET, ip, &addr) != 1) return 0;
	return ntohl(addr.s_addr);
}

/**
 * Checks if an IPv4 address (as uint32_t) falls within a given CIDR network.
 *
 * @param ip IP address to check.
 * @param network Network base address.
 * @param mask Network subnet mask.
 * @return int 1 if inside the CIDR, 0 otherwise.
 */
int sg_ipv4_in_cidr(uint32_t ip, uint32_t network, uint32_t mask)
{
	return (ip & mask) == (network & mask);
}

/**
 * Parses an IPv4 CIDR string (e.g., "192.168.1.0/24") into a network and mask pair.
 *
 * @param cidr CIDR string to parse.
 * @param network_out Pointer to store the network address.
 * @param mask_out Pointer to store the subnet mask.
 * @return int 1 on success, 0 on failure.
 */
int sg_parse_cidr(const char *cidr, uint32_t *network_out, uint32_t *mask_out)
{
	char ip_buf[64];
	const char *slash = strchr(cidr, '/');
	if (!slash) return 0;

	size_t ip_len = (size_t)(slash - cidr);
	if (ip_len == 0 || ip_len >= sizeof(ip_buf)) return 0;
	memcpy(ip_buf, cidr, ip_len);
	ip_buf[ip_len] = '\0';

	char *endptr;
	long prefix = strtol(slash + 1, &endptr, 10);
	if (*endptr != '\0' || prefix < 0 || prefix > 32) return 0;

	struct in_addr addr;
	if (inet_pton(AF_INET, ip_buf, &addr) != 1) return 0;

	uint32_t mask = (prefix == 0) ? 0 : (~0U << (32 - (unsigned)prefix));
	*network_out = ntohl(addr.s_addr);
	*mask_out    = mask;
	return 1;
}

/* Private RFC1918 / loopback / link-local ranges */
static const struct { uint32_t net; uint32_t mask; } sg_private_ranges[] = {
	{ 0x7F000000, 0xFF000000 },  /* 127.0.0.0/8 */
	{ 0x0A000000, 0xFF000000 },  /* 10.0.0.0/8 */
	{ 0xAC100000, 0xFFF00000 },  /* 172.16.0.0/12 */
	{ 0xC0A80000, 0xFFFF0000 },  /* 192.168.0.0/16 */
	{ 0xA9FE0000, 0xFFFF0000 },  /* 169.254.0.0/16 */
};

/**
 * Checks if an IP address belongs to a private or restricted network.
 *
 * @param ip IP address string (IPv4 or IPv6).
 * @return int 1 if private, 0 otherwise.
 */
int sg_ip_is_private(const char *ip)
{
	if (!sg_is_ipv4(ip)) {
		/* For IPv6, check loopback and ULA */
		struct in6_addr addr6;
		char buf[128] = {0};
		const char *s = ip;
		if (s[0] == '[') {
			size_t len = strlen(s);
			if (len > 2 && s[len-1] == ']') {
				len -= 2;
				if (len < sizeof(buf)) {
					memcpy(buf, s+1, len);
					buf[len] = '\0';
					s = buf;
				}
			}
		}
		if (inet_pton(AF_INET6, s, &addr6) == 1) {
			/* ::1 loopback */
			struct in6_addr loopback = IN6ADDR_LOOPBACK_INIT;
			if (memcmp(&addr6, &loopback, 16) == 0) return 1;
			/* fc00::/7 ULA */
			if ((addr6.s6_addr[0] & 0xFE) == 0xFC) return 1;
			/* fe80::/10 link-local */
			if (addr6.s6_addr[0] == 0xFE && (addr6.s6_addr[1] & 0xC0) == 0x80) return 1;
		}
		return 0;
	}

	uint32_t ip32 = sg_ipv4_to_uint32(ip);
	for (size_t i = 0; i < sizeof(sg_private_ranges)/sizeof(sg_private_ranges[0]); i++) {
		if (sg_ipv4_in_cidr(ip32, sg_private_ranges[i].net, sg_private_ranges[i].mask)) {
			return 1;
		}
	}
	return 0;
}

/* Metadata endpoint host names */
static const char *sg_metadata_hosts[] = {
	"169.254.169.254",
	"metadata.google.internal",
	"metadata",
	NULL
};

/**
 * Checks if a host is a known cloud metadata endpoint.
 *
 * @param host Hostname or IP string.
 * @return int 1 if it is a metadata host, 0 otherwise.
 */
int sg_is_metadata_host(const char *host)
{
	if (!host) return 0;
	for (int i = 0; sg_metadata_hosts[i]; i++) {
		if (strcasecmp(host, sg_metadata_hosts[i]) == 0) return 1;
	}
	return 0;
}

/* Dangerous shell operators */
static const char *sg_dangerous_ops[] = {
	";", "&&", "||", "|", ">>", ">", "<", "`", "$(", "${", "\n", "\r", NULL
};

/**
 * Checks if a command string contains dangerous shell operators.
 *
 * @param cmd Command string to check.
 * @return int 1 if dangerous operators are found, 0 otherwise.
 */
int sg_command_has_dangerous_operator(const char *cmd)
{
	if (!cmd) return 0;
	for (int i = 0; sg_dangerous_ops[i]; i++) {
		if (strstr(cmd, sg_dangerous_ops[i])) return 1;
	}
	return 0;
}

/**
 * Extracts the binary path and arguments from a shell command string.
 *
 * @param cmd The shell command string.
 * @param binary_out Buffer to store the extracted binary path.
 * @param binary_len Size of the binary buffer.
 * @param args_out Buffer to store the arguments.
 * @param args_len Size of the arguments buffer.
 * @return int 1 on success, 0 on failure.
 */
int sg_extract_binary(const char *cmd, char *binary_out, size_t binary_len,
                       char *args_out, size_t args_len)
{
	if (!cmd || !binary_out || !args_out) return 0;
	binary_out[0] = '\0';
	args_out[0]   = '\0';

	/* skip leading spaces */
	while (*cmd && isspace((unsigned char)*cmd)) cmd++;
	if (!*cmd) return 0;

	const char *start = cmd;
	const char *end   = cmd;
	while (*end && !isspace((unsigned char)*end)) end++;

	size_t blen = (size_t)(end - start);
	if (blen == 0 || blen >= binary_len) return 0;
	memcpy(binary_out, start, blen);
	binary_out[blen] = '\0';

	/* args: skip whitespace after binary */
	while (*end && isspace((unsigned char)*end)) end++;
	size_t alen = strlen(end);
	if (alen >= args_len) alen = args_len - 1;
	memcpy(args_out, end, alen);
	args_out[alen] = '\0';

	return 1;
}

/**
 * Checks if a given path is an absolute path.
 *
 * @param path The path string to check.
 * @return int 1 if absolute, 0 otherwise.
 */
int sg_is_absolute_path(const char *path)
{
	return path && path[0] == '/';
}

/**
 * Checks if a path contains directory traversal sequences (e.g., "../").
 *
 * @param path The path string to check.
 * @return int 1 if traversal sequences are found, 0 otherwise.
 */
int sg_has_path_traversal(const char *path)
{
	if (!path) return 0;
	/* Check for .. component */
	if (strstr(path, "/../") || strstr(path, "/..")) {
		const char *p = strstr(path, "/..");
		while (p) {
			char after = p[3];
			if (after == '/' || after == '\0') return 1;
			p = strstr(p + 1, "/..");
		}
	}
	/* Check for relative traversal at start */
	if (strncmp(path, "../", 3) == 0 || strcmp(path, "..") == 0) return 1;
	return 0;
}

/**
 * Resolves the absolute path of a file, resolving all symlinks.
 *
 * @param path Path to resolve.
 * @return char* Allocated absolute path. Must be freed with estrdup().
 */
char *sg_resolve_realpath(const char *path)
{
	if (!path) return NULL;
	char resolved[PATH_MAX];
	if (realpath(path, resolved) == NULL) return NULL;
	return estrdup(resolved);
}

/**
 * Generates an ISO 8601 formatted timestamp string with timezone offset.
 * Example: 2026-05-04T15:30:00-03:00
 *
 * @param buf Buffer to store the formatted timestamp.
 * @param len Size of the buffer.
 */
void sg_timestamp_now(char *buf, size_t len)
{
	time_t t = time(NULL);
	struct tm *tm_info = localtime(&t);
	if (!tm_info || !buf || len == 0) return;
	/* Format: 2026-05-04T15:30:00-03:00 */
	strftime(buf, len, "%Y-%m-%dT%H:%M:%S%z", tm_info);
	/* Insert colon into timezone offset: -0300 → -03:00 */
	size_t written = strlen(buf);
	if (written >= 5) {
		char *tz = buf + written - 5;
		/* shift last 2 chars right by 1 to insert colon */
		if (tz[0] == '+' || tz[0] == '-') {
			memmove(tz + 3, tz + 2, 3);
			tz[3] = ':';
		}
	}
}

/**
 * Retrieves the effective username and UID of the current process.
 *
 * @param user_out Buffer to store the username.
 * @param user_len Length of the buffer.
 * @param uid_out Pointer to store the UID.
 */
void sg_get_effective_user(char *user_out, size_t user_len, int *uid_out)
{
	uid_t uid = geteuid();
	if (uid_out) *uid_out = (int)uid;
	if (!user_out || user_len == 0) return;

	struct passwd *pw = getpwuid(uid);
	if (pw && pw->pw_name) {
		strncpy(user_out, pw->pw_name, user_len - 1);
		user_out[user_len - 1] = '\0';
	} else {
		snprintf(user_out, user_len, "%d", (int)uid);
	}
}

/**
 * Gets the filename of the current PHP script being executed.
 *
 * @return const char* Pointer to the filename string.
 */
const char *sg_current_script(void)
{
	zend_string *filename = NULL;
	if (EG(current_execute_data) && EG(current_execute_data)->func &&
	    EG(current_execute_data)->func->type == ZEND_USER_FUNCTION) {
		filename = EG(current_execute_data)->func->op_array.filename;
	}
	if (!filename && zend_is_executing()) {
		const char *sf = zend_get_executed_filename();
		return sf ? sf : "unknown";
	}
	return filename ? ZSTR_VAL(filename) : "unknown";
}

/**
 * Escapes a string to make it safe for inclusion within a JSON string literal.
 * Handles quotes, backslashes, and control characters.
 *
 * @param in The raw input string.
 * @param out Buffer to store the escaped JSON string.
 * @param out_len Size of the output buffer.
 */
void sg_json_escape(const char *in, char *out, size_t out_len)
{
	if (!in || !out || out_len == 0) return;
	size_t i = 0, j = 0;
	while (in[i] && j + 2 < out_len) {
		unsigned char c = (unsigned char)in[i];
		switch (c) {
			case '"':  out[j++] = '\\'; out[j++] = '"';  break;
			case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
			case '\n': out[j++] = '\\'; out[j++] = 'n';  break;
			case '\r': out[j++] = '\\'; out[j++] = 'r';  break;
			case '\t': out[j++] = '\\'; out[j++] = 't';  break;
			default:
				if (c < 0x20) {
					if (j + 6 < out_len) {
						j += snprintf(out + j, out_len - j, "\\u%04x", c);
					}
				} else {
					out[j++] = (char)c;
				}
		}
		i++;
	}
	out[j] = '\0';
}

/**
 * Frees a configuration entry and its strings.
 *
 * @param entry The entry to free.
 */
void sg_entry_free(sg_entry_t *entry)
{
	if (!entry) return;
	if (entry->value) efree(entry->value);
	if (entry->raw)   efree(entry->raw);
	efree(entry);
}

/**
 * Frees a security decision structure and all its dynamically allocated strings.
 *
 * @param dec The decision structure to free.
 */
void sg_decision_free(sg_decision_t *dec)
{
	if (!dec) return;
	if (dec->function_name)  efree(dec->function_name);
	if (dec->target)         efree(dec->target);
	if (dec->realpath_val)   efree(dec->realpath_val);
	if (dec->scheme)         efree(dec->scheme);
	if (dec->host)           efree(dec->host);
	if (dec->host_type)      efree(dec->host_type);
	if (dec->rule_matched)   efree(dec->rule_matched);
	if (dec->command_binary) efree(dec->command_binary);
	if (dec->command_args)   efree(dec->command_args);
	efree(dec);
}
