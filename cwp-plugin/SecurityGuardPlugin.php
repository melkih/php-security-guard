<?php
declare(strict_types=1);

/**
 * CWP PHP Security Guard Plugin
 *
 * Manages whitelists for the security_guard PHP extension.
 * Intended for use inside a CWP admin module context.
 *
 * @package php-security-guard
 * @author @melkih (with AI)
 */
class SecurityGuardPlugin
{
    /** @var string Path to the allowed commands configuration file */
    private string $commandsFile;

    /** @var string Path to the allowed files configuration file */
    private string $filesFile;

    /** @var string Path to the allowed network configuration file */
    private string $networkFile;

    /** @var string Path to the administrator actions log file */
    private string $adminLogFile;

    /**
     * Constructor
     *
     * @param string $commandsFile Path to commands whitelist
     * @param string $filesFile Path to files whitelist
     * @param string $networkFile Path to network whitelist
     * @param string $adminLog Path to admin audit log
     */
        string $commandsFile = '/etc/security_guard/allowed_commands.conf',
        string $filesFile    = '/etc/security_guard/allowed_files.conf',
        string $networkFile  = '/etc/security_guard/allowed_network.conf',
        string $adminLog     = '/var/log/security_guard/admin_actions.log'
    ) {
        $this->commandsFile = $commandsFile;
        $this->filesFile    = $filesFile;
        $this->networkFile  = $networkFile;
        $this->adminLogFile = $adminLog;
    }

    /* ------------------------------------------------------------------ */
    /* Public API                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Lists all allowed commands from the configuration file.
     *
     * @return array List of commands with metadata (type, value, date, user, obs)
     */
    {
        return $this->loadConf($this->commandsFile, ['command']);
    }

    /**
     * Adds a command to the allowed list.
     *
     * @param string $binary Absolute path to the binary
     * @param string $adminUser The administrator performing the action
     * @param string $sourceIp IP address of the administrator
     * @param string $obs Optional observation/reason
     * @return bool True on success, false otherwise
     */
    {
        if (!$this->validateBinaryPath($binary)) return false;
        return $this->appendEntry($this->commandsFile, 'command', $binary, $adminUser, $sourceIp, $obs, 'add');
    }

    /**
     * Removes a command from the allowed list.
     *
     * @param string $binary Absolute path to the binary to remove
     * @param string $adminUser The administrator performing the action
     * @param string $sourceIp IP address of the administrator
     * @return bool True if removed, false if not found or failed
     */
    {
        return $this->removeEntry($this->commandsFile, 'command', $binary, $adminUser, $sourceIp);
    }

    /**
     * Lists all allowed file paths from the configuration file.
     *
     * @return array List of files with metadata
     */
    {
        return $this->loadConf($this->filesFile, ['file']);
    }

    /**
     * Adds a file path to the allowed list.
     *
     * @param string $path Absolute path to the file
     * @param string $adminUser The administrator performing the action
     * @param string $sourceIp IP address of the administrator
     * @param string $obs Optional observation/reason
     * @return bool True on success, false otherwise
     */
    {
        if (!$this->validateFilePath($path)) return false;
        return $this->appendEntry($this->filesFile, 'file', $path, $adminUser, $sourceIp, $obs, 'add');
    }

    /**
     * Removes a file path from the allowed list.
     *
     * @param string $path Absolute path to the file to remove
     * @param string $adminUser The administrator performing the action
     * @param string $sourceIp IP address of the administrator
     * @return bool True if removed, false if not found or failed
     */
    {
        return $this->removeEntry($this->filesFile, 'file', $path, $adminUser, $sourceIp);
    }

    /**
     * Lists all allowed network targets from the configuration file.
     *
     * @return array List of network entries (domain, url, ip, cidR) with metadata
     */
    {
        return $this->loadConf($this->networkFile, ['domain', 'url', 'ip', 'cidr']);
    }

    /**
     * Adds a network target to the allowed list.
     *
     * @param string $type Entry type: 'domain', 'url', 'ip', or 'cidr'
     * @param string $value The target value
     * @param string $adminUser The administrator performing the action
     * @param string $sourceIp IP address of the administrator
     * @param string $obs Optional observation/reason
     * @return bool True on success, false otherwise
     */
    {
        if (!in_array($type, ['domain', 'url', 'ip', 'cidr'], true)) return false;
        if (!$this->validateNetworkValue($type, $value, $adminUser)) return false;
        return $this->appendEntry($this->networkFile, $type, $value, $adminUser, $sourceIp, $obs, 'add');
    }

    /**
     * Removes a network target from the allowed list.
     *
     * @param string $type Entry type
     * @param string $value The target value to remove
     * @param string $adminUser The administrator performing the action
     * @param string $sourceIp IP address of the administrator
     * @return bool True if removed, false if not found or failed
     */
    {
        return $this->removeEntry($this->networkFile, $type, $value, $adminUser, $sourceIp);
    }

    /**
     * Validates the structure and readability of a configuration file.
     *
     * @param string $path Path to the configuration file
     * @return array List of error messages, empty if valid
     */
    {
        $errors = [];
        $lines  = @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return ["Cannot read file: $path"];
        }
        foreach ($lines as $i => $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            $parts = explode('|', $line);
            if (count($parts) < 4) {
                $errors[] = "Line " . ($i + 1) . ": insufficient fields";
            }
        }
        return $errors;
    }

    /* ------------------------------------------------------------------ */
    /* Validation                                                           */
    /* ------------------------------------------------------------------ */

    /**
     * Validates if a binary path is safe and absolute.
     *
     * @param string $binary Path to check
     * @return bool
     */
    {
        /* Must be absolute */
        if (!str_starts_with($binary, '/')) return false;
        /* No arguments or operators */
        if (preg_match('/[\s;&|><`$]/', $binary)) return false;
        /* Must exist */
        if (!is_file($binary)) return false;
        return true;
    }

    /**
     * Validates if a file path is safe and absolute.
     *
     * @param string $path Path to check
     * @return bool
     */
    {
        if (!str_starts_with($path, '/')) return false;
        if (str_contains($path, '..')) return false;
        return true;
    }

    /**
     * Validates network values according to their type.
     *
     * @param string $type 'domain', 'url', 'ip', or 'cidr'
     * @param string $value The value to validate
     * @param string $adminUser The admin user (for wildcard logic checks)
     * @return bool
     */
    {
        $value = strtolower(rtrim($value, '.'));
        switch ($type) {
            case 'domain':
                if (str_starts_with($value, '*.')) {
                    /* Wildcard: base domain must already exist */
                    $base = substr($value, 2);
                    if (!$this->domainExistsInConf($base)) {
                        error_log("security_guard CWP: wildcard $value requires $base to be present first");
                        return false;
                    }
                }
                return $this->isValidDomain($value);
            case 'url':
                return (bool)filter_var($value, FILTER_VALIDATE_URL);
            case 'ip':
                return (bool)filter_var($value, FILTER_VALIDATE_IP);
            case 'cidr':
                return $this->isValidCidr($value);
        }
        return false;
    }

    /**
     * Validates domain name format.
     *
     * @param string $domain Domain or wildcard domain
     * @return bool
     */
    {
        $d = ltrim($domain, '*.');
        return (bool)preg_match('/^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$/i', $d);
    }

    /**
     * Validates CIDR notation for IPv4 and IPv6.
     *
     * @param string $cidr CIDR string
     * @return bool
     */
    {
        if (!str_contains($cidr, '/')) return false;
        [$ip, $prefix] = explode('/', $cidr, 2);
        if (str_contains($ip, ':')) {
            /* IPv6 */
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) return false;
            return is_numeric($prefix) && (int)$prefix >= 0 && (int)$prefix <= 128;
        }
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) return false;
        return is_numeric($prefix) && (int)$prefix >= 0 && (int)$prefix <= 32;
    }

    /**
     * Checks if a base domain is already in the configuration.
     * Used for validating wildcard additions.
     *
     * @param string $domain Domain to search for
     * @return bool
     */
    {
        $entries = $this->loadConf($this->networkFile, ['domain']);
        foreach ($entries as $e) {
            if (strtolower($e['value']) === strtolower($domain)) return true;
        }
        return false;
    }

    /* ------------------------------------------------------------------ */
    /* File I/O                                                             */
    /* ------------------------------------------------------------------ */

    /**
     * Loads and parses a configuration file.
     *
     * @param string $file Path to file
     * @param array $typeFilter Types of entries to load
     * @return array
     */
    {
        $entries = [];
        $seen    = [];
        $lines   = @file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) return $entries;

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') continue;
            $parts = explode('|', $line);
            if (count($parts) < 4) continue;
            $type  = trim($parts[0]);
            $value = trim($parts[1]);
            $date  = trim($parts[2]);
            $user  = trim($parts[3]);
            $obs   = trim($parts[4] ?? '');
            if (!in_array($type, $typeFilter, true)) continue;

            $key = $type . '|' . strtolower(rtrim($value, '.'));
            if (isset($seen[$key])) continue; /* deduplicate */
            $seen[$key] = true;

            $entries[] = compact('type', 'value', 'date', 'user', 'obs');
        }
        return $entries;
    }

    /**
     * Appends a new entry to a configuration file with duplicate checking.
     *
     * @param string $file Target file
     * @param string $type Entry type
     * @param string $value Entry value
     * @param string $adminUser Admin user
     * @param string $sourceIp Admin IP
     * @param string $obs Observation
     * @param string $action Action name for logging
     * @return bool
     */
    {
        /* Check for duplicate */
        $existing = $this->loadConf($file, [$type]);
        $normKey  = strtolower(rtrim($value, '.'));
        foreach ($existing as $e) {
            if (strtolower(rtrim($e['value'], '.')) === $normKey) {
                $this->auditLog($adminUser, 'add_duplicate', $file, $type, $value, 'duplicate', $sourceIp);
                return false; /* Already exists */
            }
        }

        $ts   = (new DateTimeImmutable())->format('Y-m-d\TH:i:sP');
        $line = implode('|', [$type, $value, $ts, $adminUser, $obs]);

        $written = $this->atomicAppend($file, $line . "\n");
        if ($written) {
            $this->auditLog($adminUser, $action, $file, $type, $value, 'created', $sourceIp);
        }
        return $written;
    }

    /**
     * Removes an entry from a configuration file.
     *
     * @param string $file Target file
     * @param string $type Entry type
     * @param string $value Entry value to remove
     * @param string $adminUser Admin user
     * @param string $sourceIp Admin IP
     * @return bool
     */
    {
        $lines   = @file($file, FILE_IGNORE_NEW_LINES) ?: [];
        $normKey = strtolower(rtrim($value, '.'));
        $out     = [];
        $removed = false;

        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || $trimmed[0] === '#') {
                $out[] = $line;
                continue;
            }
            $parts = explode('|', $trimmed);
            if (count($parts) >= 2 &&
                trim($parts[0]) === $type &&
                strtolower(rtrim(trim($parts[1]), '.')) === $normKey) {
                $removed = true;
                continue;
            }
            $out[] = $line;
        }

        if (!$removed) return false;

        $written = $this->atomicWrite($file, implode("\n", $out) . "\n");
        if ($written) {
            $this->auditLog($adminUser, 'remove', $file, $type, $value, 'removed', $sourceIp);
        }
        return $written;
    }

    /**
     * Appends content to a file atomically using a temporary file.
     *
     * @param string $file Target file
     * @param string $content Content to append
     * @return bool
     */
    {
        $tmp = $file . '.tmp.' . getmypid();
        $existing = @file_get_contents($file) ?: '';
        if (file_put_contents($tmp, $existing . $content, LOCK_EX) === false) return false;
        chmod($tmp, 0640);
        return rename($tmp, $file);
    }

    /**
     * Overwrites a file atomically using a temporary file.
     *
     * @param string $file Target file
     * @param string $content New content
     * @return bool
     */
    {
        $tmp = $file . '.tmp.' . getmypid();
        if (file_put_contents($tmp, $content, LOCK_EX) === false) return false;
        chmod($tmp, 0640);
        return rename($tmp, $file);
    }

    /* ------------------------------------------------------------------ */
    /* Audit log                                                            */
    /* ------------------------------------------------------------------ */

    /**
     * Logs administrative actions to the audit log in JSONL format.
     *
     * @param string $adminUser Admin user
     * @param string $action Action performed
     * @param string $file Target config file
     * @param string $entryType Type of entry affected
     * @param string $entryValue Value of entry affected
     * @param string $result Outcome of the action
     * @param string $sourceIp Admin source IP
     * @return void
     */
    {
        $ts = (new DateTimeImmutable())->format('Y-m-d\TH:i:sP');
        $entry = json_encode([
            'ts'          => $ts,
            'admin_user'  => $adminUser,
            'action'      => $action,
            'file'        => basename($file),
            'entry_type'  => $entryType,
            'entry_value' => $entryValue,
            'result'      => $result,
            'source_ip'   => $sourceIp,
        ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        @file_put_contents($this->adminLogFile, $entry . "\n", FILE_APPEND | LOCK_EX);
    }
}
