/**
 * Logger Implementation for security_guard
 *
 * Handles logging of allowed and denied actions in both plain text and JSONL formats.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
#include "logger.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>

/**
 * Checks if the log rate limit has been reached for the current request.
 *
 * @return int 1 if allowed to log, 0 if rate limited.
 */
int sg_log_rate_check(void)
{
	zend_long limit = SG_G(log_rate_limit);
	if (limit <= 0) return 1;
	if (SG_G(log_rate_count) >= limit) return 0;
	SG_G(log_rate_count)++;
	return 1;
}

/**
 * Determines the effective log file path based on configuration (global vs per-user).
 *
 * @return char* Allocated string with the path. Must be freed with efree().
 */
char *sg_log_file_path(void)
{
	const char *base = SG_G(log_path);
	if (!base || !*base) base = "/var/log/security_guard";

	char *path;
	if (SG_G(log_scope) == SG_LOG_SCOPE_PER_USER) {
		const char *user = SG_G(current_user);
		if (!user || !*user) user = "unknown";
		/* +32 for /users/ + user + .log + null */
		size_t len = strlen(base) + strlen(user) + 32;
		path = emalloc(len);
		snprintf(path, len, "%s/users/%s.log", base, user);
	} else {
		size_t len = strlen(base) + 32;
		path = emalloc(len);
		snprintf(path, len, "%s/security_guard.log", base);
	}
	return path;
}

/**
 * Writes a formatted log line to the appropriate log file.
 *
 * @param line The null-terminated string to write.
 */
static void sg_write_log_line(const char *line)
{
	char *path = sg_log_file_path();
	FILE *fp = fopen(path, "a");
	if (fp) {
		fputs(line, fp);
		fputc('\n', fp);
		fclose(fp);
	}
	efree(path);
}

/**
 * Builds a JSONL formatted log entry from a decision structure.
 *
 * @param dec The security decision to log.
 * @param action The action performed (allow, deny, monitor_violation).
 * @param buf The buffer to write the JSON string into.
 * @param buf_len The size of the buffer.
 */
static void sg_build_jsonl(sg_decision_t *dec, const char *action, char *buf, size_t buf_len)
{
	char ts[64];
	sg_timestamp_now(ts, sizeof(ts));

	char target_esc[SG_MAX_URL_LEN * 2 + 4] = {0};
	if (dec->target) sg_json_escape(dec->target, target_esc, sizeof(target_esc));

	char script_esc[SG_MAX_PATH_LEN * 2 + 4] = {0};
	const char *script = sg_current_script();
	if (script) sg_json_escape(script, script_esc, sizeof(script_esc));

	const char *user = SG_G(current_user) ? SG_G(current_user) : "unknown";
	int uid = SG_G(current_uid);

	const char *group_str = "unknown";
	if (dec->group == SG_GROUP_COMMAND) group_str = "command";
	else if (dec->group == SG_GROUP_FILE) group_str = "file";
	else if (dec->group == SG_GROUP_NETWORK) group_str = "network";

	const char *mode_str = "off";
	if (SG_G(enforcement_mode) == SG_MODE_MONITOR) mode_str = "monitor";
	else if (SG_G(enforcement_mode) == SG_MODE_BLOCK) mode_str = "block";

	/* Base fields */
	int written = snprintf(buf, buf_len,
		"{\"ts\":\"%s\",\"action\":\"%s\",\"group\":\"%s\","
		"\"function\":\"%s\",\"user\":\"%s\",\"uid\":%d,"
		"\"script\":\"%s\",\"target\":\"%s\","
		"\"reason\":\"%s\",\"mode\":\"%s\"",
		ts, action, group_str,
		dec->function_name ? dec->function_name : "",
		user, uid,
		script_esc, target_esc,
		dec->reason ? dec->reason : "",
		mode_str);

	/* Optional fields */
	if (dec->scheme && written < (int)buf_len) {
		written += snprintf(buf + written, buf_len - written,
			",\"scheme\":\"%s\"", dec->scheme);
	}
	if (dec->host && written < (int)buf_len) {
		char host_esc[512] = {0};
		sg_json_escape(dec->host, host_esc, sizeof(host_esc));
		written += snprintf(buf + written, buf_len - written,
			",\"host\":\"%s\"", host_esc);
	}
	if (dec->port > 0 && written < (int)buf_len) {
		written += snprintf(buf + written, buf_len - written,
			",\"port\":%d", dec->port);
	}
	if (dec->host_type && written < (int)buf_len) {
		written += snprintf(buf + written, buf_len - written,
			",\"host_type\":\"%s\"", dec->host_type);
	}
	if (dec->command_binary && written < (int)buf_len) {
		char bin_esc[512] = {0};
		sg_json_escape(dec->command_binary, bin_esc, sizeof(bin_esc));
		written += snprintf(buf + written, buf_len - written,
			",\"command_binary\":\"%s\"", bin_esc);
	}
	if (dec->command_args && *dec->command_args && written < (int)buf_len) {
		char args_esc[1024] = {0};
		sg_json_escape(dec->command_args, args_esc, sizeof(args_esc));
		written += snprintf(buf + written, buf_len - written,
			",\"command_args\":\"%s\"", args_esc);
	}
	if (dec->realpath_val && written < (int)buf_len) {
		char rp_esc[SG_MAX_PATH_LEN] = {0};
		sg_json_escape(dec->realpath_val, rp_esc, sizeof(rp_esc));
		written += snprintf(buf + written, buf_len - written,
			",\"realpath\":\"%s\"", rp_esc);
	}
	if (dec->rule_matched && written < (int)buf_len) {
		char rule_esc[512] = {0};
		sg_json_escape(dec->rule_matched, rule_esc, sizeof(rule_esc));
		written += snprintf(buf + written, buf_len - written,
			",\"rule\":\"%s\"", rule_esc);
	}
	if (SG_G(log_backtrace) && written < (int)buf_len) {
		/* Add PID at minimum when backtrace is enabled */
		written += snprintf(buf + written, buf_len - written,
			",\"pid\":%d", (int)getpid());
	}

	/* close JSON */
	if (written < (int)buf_len - 2) {
		buf[written++] = '}';
		buf[written]   = '\0';
	}
}

/**
 * Builds a plain text formatted log entry from a decision structure.
 *
 * @param dec The security decision to log.
 * @param action The action performed.
 * @param buf The buffer to write the plain text string into.
 * @param buf_len The size of the buffer.
 */
static void sg_build_plain(sg_decision_t *dec, const char *action, char *buf, size_t buf_len)
{
	char ts[64];
	sg_timestamp_now(ts, sizeof(ts));
	const char *user = SG_G(current_user) ? SG_G(current_user) : "unknown";
	const char *script = sg_current_script();

	snprintf(buf, buf_len,
		"[%s] %s %s() target=%s user=%s script=%s reason=%s",
		ts, action,
		dec->function_name ? dec->function_name : "",
		dec->target ? dec->target : "",
		user, script ? script : "",
		dec->reason ? dec->reason : "");
}

/**
 * Dispatches the log writing process by formatting the message and writing to the file.
 * Subject to rate limiting.
 *
 * @param dec The security decision to log.
 * @param action The action string.
 */
static void sg_log_write(sg_decision_t *dec, const char *action)
{
	if (!sg_log_rate_check()) return;

	char buf[SG_MAX_URL_LEN * 4];

	if (SG_G(log_format) == SG_LOG_FORMAT_JSONL) {
		sg_build_jsonl(dec, action, buf, sizeof(buf));
	} else {
		sg_build_plain(dec, action, buf, sizeof(buf));
	}

	sg_write_log_line(buf);
}

/**
 * Logs an allowed action.
 *
 * @param dec Pointer to the decision structure.
 */
void sg_log_allow(sg_decision_t *dec)
{
	if (!SG_G(log_allowed)) return;
	sg_log_write(dec, "allow");
}

/**
 * Logs a denied action.
 *
 * @param dec Pointer to the decision structure.
 */
void sg_log_deny(sg_decision_t *dec)
{
	if (!SG_G(log_denied)) return;
	sg_log_write(dec, "deny");
}

/**
 * Logs a violation that occurred while in monitor mode.
 *
 * @param dec Pointer to the decision structure.
 */
void sg_log_monitor_violation(sg_decision_t *dec)
{
	/* In monitor mode: log denied calls but don't block */
	if (!SG_G(log_denied)) return;
	sg_log_write(dec, "monitor_violation");
}
