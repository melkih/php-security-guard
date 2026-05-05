# Audit Logs and Monitoring

PHP Security Guard generates structured audit logs in JSONL (JSON Lines) format, making it easy to monitor activity and integrate with log management tools.

### Log File Location
Depending on `security_guard.log_scope`:
*   **global**: `/var/log/security_guard/audit.log`
*   **per_user**: `/var/log/security_guard/audit_UID.log` (e.g., `audit_1005.log`)

### JSON Fields Reference

| Field | Description |
|-------|-------------|
| `ts` | RFC3339 Timestamp. |
| `action` | `allow` (authorized) or `deny` (blocked/violation). |
| `group` | `command`, `file`, or `network`. |
| `function` | The PHP function called (e.g., `exec`, `curl_exec`). |
| `user` | The Linux username executing the script. |
| `uid` | The Linux UID. |
| `script` | Absolute path to the PHP script that initiated the call. |
| `target` | The command string, file path, or URL being accessed. |
| `reason` | Technical reason for the decision (e.g., `domain_not_whitelisted`). |
| `mode` | The enforcement mode active at the time (`monitor` or `block`). |

### Example Log Entries

**Denied Command (Block Mode)**
```json
{"ts":"2026-05-04T15:32:00-03:00","action":"deny","group":"command","function":"shell_exec","user":"client1","uid":1005,"script":"/home/client1/public_html/shell.php","target":"rm -rf /","reason":"command_not_whitelisted","mode":"block"}
```

**Denied Network (SSRF Protection)**
```json
{"ts":"2026-05-04T15:31:00-03:00","action":"deny","group":"network","function":"file_get_contents","user":"client1","uid":1005,"script":"/home/client1/public_html/test.php","target":"http://169.254.169.254/latest/meta-data/","scheme":"http","host":"169.254.169.254","port":80,"host_type":"ip","reason":"private_network_blocked","mode":"block"}
```

### Tips for Monitoring
1.  **Fail2Ban Integration**: You can create a Fail2Ban filter to monitor `audit.log` for high frequencies of `action: deny` from the same user.
2.  **Dashboarding**: Ingest these JSONL files into ELK (Elasticsearch, Logstash, Kibana) or Grafana Loki to visualize which users are triggering the most security violations.
