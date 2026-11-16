<?php

/**
 * ------------------------------------------------------------------------
 * Security Guard - Gerenciamento de configuração global
 *
 * Copyright (C) 2026 by G. Martins
 * ------------------------------------------------------------------------
 *
 * LICENSE
 *
 * This file is part of Security Guard.
 *
 * Security Guard is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Security Guard is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 * ------------------------------------------------------------------------
 */

if (!defined('GLPI_ROOT')) {
    die("Sorry. You can't access this file directly");
}

interface PluginSecurityguardConfigConstants
{
    public const CONTEXT = 'plugin:securityguard';

    public const DEFAULT_ENABLED         = 1;
    public const DEFAULT_MAX_ATTEMPTS    = 5;
    public const DEFAULT_WINDOW_MINUTES  = 15;
    public const DEFAULT_LOCKOUT_MINUTES = 15;
    public const DEFAULT_TRUST_PROXY     = 0;
    public const DEFAULT_AUDIT_LOGINS    = 1;
    public const DEFAULT_AUDIT_CHANGES   = 1;
    public const DEFAULT_RETENTION_DAYS  = 90;
}

trait PluginSecurityguardConfigBody
{
    public static function getTypeName($nb = 0)
    {
        return __('Security Guard', 'securityguard');
    }

    /**
     * Retorna valores padrão da configuração do plugin.
     *
     * @return array<string, int|string>
     */
    public static function defaults(): array
    {
        return [
            'enabled'         => self::DEFAULT_ENABLED,
            'max_attempts'    => self::DEFAULT_MAX_ATTEMPTS,
            'window_minutes'  => self::DEFAULT_WINDOW_MINUTES,
            'lockout_minutes' => self::DEFAULT_LOCKOUT_MINUTES,
            'trust_proxy'     => self::DEFAULT_TRUST_PROXY,
            'trusted_proxies' => '',
            'ip_allowlist'    => '',
            'audit_logins'    => self::DEFAULT_AUDIT_LOGINS,
            'audit_changes'   => self::DEFAULT_AUDIT_CHANGES,
            'retention_days'  => self::DEFAULT_RETENTION_DAYS,
        ];
    }

    /**
     * Lê e normaliza a configuração atual armazenada em glpi_configs.
     *
     * @return array<string, int|string>
     */
    public static function getConfig(): array
    {
        $defaults = self::defaults();
        $stored   = [];

        if (class_exists('Config') && method_exists('Config', 'getConfigurationValues')) {
            $raw = Config::getConfigurationValues(self::CONTEXT);
            if (is_array($raw)) {
                $stored = $raw;
            }
        }

        return [
            'enabled'         => self::clampBool($stored['enabled'] ?? $defaults['enabled']),
            'max_attempts'    => self::clampInt($stored['max_attempts'] ?? $defaults['max_attempts'], 3, 50, self::DEFAULT_MAX_ATTEMPTS),
            'window_minutes'  => self::clampInt($stored['window_minutes'] ?? $defaults['window_minutes'], 1, 1440, self::DEFAULT_WINDOW_MINUTES),
            'lockout_minutes' => self::clampInt($stored['lockout_minutes'] ?? $defaults['lockout_minutes'], 1, 1440, self::DEFAULT_LOCKOUT_MINUTES),
            'trust_proxy'     => self::clampBool($stored['trust_proxy'] ?? $defaults['trust_proxy']),
            'trusted_proxies' => self::normalizeIpListString((string) ($stored['trusted_proxies'] ?? $defaults['trusted_proxies'])),
            'ip_allowlist'    => self::normalizeIpListString((string) ($stored['ip_allowlist'] ?? $defaults['ip_allowlist'])),
            'audit_logins'    => self::clampBool($stored['audit_logins'] ?? $defaults['audit_logins']),
            'audit_changes'   => self::clampBool($stored['audit_changes'] ?? $defaults['audit_changes']),
            'retention_days'  => self::clampInt($stored['retention_days'] ?? $defaults['retention_days'], 1, 3650, self::DEFAULT_RETENTION_DAYS),
        ];
    }

    /**
     * Persiste e retorna a configuração normalizada.
     *
     * @param array<string, mixed> $input
     * @return array<string, int|string>
     */
    public static function saveConfig(array $input): array
    {
        $current = self::getConfig();

        $normalized = [
            'enabled'         => array_key_exists('enabled', $input) ? self::clampBool($input['enabled']) : $current['enabled'],
            'max_attempts'    => array_key_exists('max_attempts', $input)
                ? self::clampInt($input['max_attempts'], 3, 50, self::DEFAULT_MAX_ATTEMPTS)
                : $current['max_attempts'],
            'window_minutes'  => array_key_exists('window_minutes', $input)
                ? self::clampInt($input['window_minutes'], 1, 1440, self::DEFAULT_WINDOW_MINUTES)
                : $current['window_minutes'],
            'lockout_minutes' => array_key_exists('lockout_minutes', $input)
                ? self::clampInt($input['lockout_minutes'], 1, 1440, self::DEFAULT_LOCKOUT_MINUTES)
                : $current['lockout_minutes'],
            'trust_proxy'     => array_key_exists('trust_proxy', $input) ? self::clampBool($input['trust_proxy']) : $current['trust_proxy'],
            'trusted_proxies' => array_key_exists('trusted_proxies', $input)
                ? self::normalizeIpListString(PluginSecurityguardCompat::fromSanitizedInput((string) $input['trusted_proxies']))
                : $current['trusted_proxies'],
            'ip_allowlist'    => array_key_exists('ip_allowlist', $input)
                ? self::normalizeIpListString(PluginSecurityguardCompat::fromSanitizedInput((string) $input['ip_allowlist']))
                : $current['ip_allowlist'],
            'audit_logins'    => array_key_exists('audit_logins', $input) ? self::clampBool($input['audit_logins']) : $current['audit_logins'],
            'audit_changes'   => array_key_exists('audit_changes', $input) ? self::clampBool($input['audit_changes']) : $current['audit_changes'],
            'retention_days'  => array_key_exists('retention_days', $input)
                ? self::clampInt($input['retention_days'], 1, 3650, self::DEFAULT_RETENTION_DAYS)
                : $current['retention_days'],
        ];

        if (class_exists('Config') && method_exists('Config', 'setConfigurationValues')) {
            Config::setConfigurationValues(self::CONTEXT, $normalized);
        }

        return $normalized;
    }

    /**
     * Inicializa valores padrão na instalação sem sobrescrever chaves existentes.
     */
    public static function installDefaults(): void
    {
        if (!class_exists('Config') || !method_exists('Config', 'getConfigurationValues')) {
            return;
        }
        $existing = Config::getConfigurationValues(self::CONTEXT);
        if (!is_array($existing)) {
            $existing = [];
        }
        $toSet = [];
        foreach (self::defaults() as $key => $defaultVal) {
            if (!array_key_exists($key, $existing)) {
                $toSet[$key] = $defaultVal;
            }
        }
        if ($toSet !== [] && method_exists('Config', 'setConfigurationValues')) {
            Config::setConfigurationValues(self::CONTEXT, $toSet);
        }
    }

    /**
     * Remove todas as chaves de configuração do plugin na desinstalação.
     */
    public static function uninstallConfig(): void
    {
        if (class_exists('Config') && method_exists('Config', 'deleteConfigurationValues')) {
            Config::deleteConfigurationValues(self::CONTEXT, array_keys(self::defaults()));
        }
    }

    /**
     * Converte lista textual (separada por vírgula, ponto-e-vírgula ou quebra de linha) em array de IPs/CIDRs válidos.
     *
     * @return string[]
     */
    public static function parseIpList(string $raw): array
    {
        if (trim($raw) === '') {
            return [];
        }
        $parts = preg_split('/[\s,;]+/', $raw);
        if (!is_array($parts)) {
            return [];
        }
        $valid = [];
        foreach ($parts as $token) {
            $candidate = trim($token);
            if ($candidate === '') {
                continue;
            }
            if (filter_var($candidate, FILTER_VALIDATE_IP) !== false) {
                $normalized = strtolower($candidate);
                if (!in_array($normalized, $valid, true)) {
                    $valid[] = $normalized;
                }
                continue;
            }
            if (strpos($candidate, '/') !== false) {
                $cidrParts = explode('/', $candidate, 2);
                $net       = trim($cidrParts[0] ?? '');
                $maskStr   = trim($cidrParts[1] ?? '');
                if ($net !== '' && ctype_digit($maskStr)) {
                    $mask = (int) $maskStr;
                    if (filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && $mask >= 0 && $mask <= 32) {
                        $normalized = strtolower($net) . '/' . $mask;
                        if (!in_array($normalized, $valid, true)) {
                            $valid[] = $normalized;
                        }
                    } elseif (filter_var($net, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false && $mask >= 0 && $mask <= 128) {
                        $normalized = strtolower($net) . '/' . $mask;
                        if (!in_array($normalized, $valid, true)) {
                            $valid[] = $normalized;
                        }
                    }
                }
            }
        }
        return $valid;
    }

    /**
     * Verifica se um IP pertence a uma lista de IPs ou sub-redes CIDR.
     */
    public static function ipMatchesList(string $ip, string $listStr): bool
    {
        $ip = trim($ip);
        if ($ip === '' || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        $entries = self::parseIpList($listStr);
        if ($entries === []) {
            return false;
        }

        $ipBin = @inet_pton($ip);
        if ($ipBin === false) {
            return false;
        }

        foreach ($entries as $entry) {
            if (strpos($entry, '/') === false) {
                $entryBin = @inet_pton($entry);
                if ($entryBin !== false && $entryBin === $ipBin) {
                    return true;
                }
                continue;
            }

            $parts   = explode('/', $entry, 2);
            $netStr  = $parts[0] ?? '';
            $maskLen = (int) ($parts[1] ?? -1);
            $netBin  = @inet_pton($netStr);
            if ($netBin === false || strlen($netBin) !== strlen($ipBin) || $maskLen < 0) {
                continue;
            }

            $fullBytes = intdiv($maskLen, 8);
            $remBits   = $maskLen % 8;

            if ($fullBytes > 0 && substr($ipBin, 0, $fullBytes) !== substr($netBin, 0, $fullBytes)) {
                continue;
            }
            if ($remBits > 0) {
                $maskByte = (0xFF << (8 - $remBits)) & 0xFF;
                if ((ord($ipBin[$fullBytes]) & $maskByte) !== (ord($netBin[$fullBytes]) & $maskByte)) {
                    continue;
                }
            }
            return true;
        }

        return false;
    }

    private static function normalizeIpListString(string $raw): string
    {
        return implode(', ', self::parseIpList($raw));
    }

    /**
     * @param mixed $val
     */
    private static function clampBool($val): int
    {
        return ((int) $val === 1 || $val === true || $val === 'true') ? 1 : 0;
    }

    /**
     * @param mixed $val
     */
    private static function clampInt($val, int $min, int $max, int $default): int
    {
        if (!is_numeric($val)) {
            return $default;
        }
        $intVal = (int) $val;
        if ($intVal < $min) {
            return $min;
        }
        if ($intVal > $max) {
            return $max;
        }
        return $intVal;
    }
}

if (PluginSecurityguardCompat::typedRightname()) {
    class PluginSecurityguardConfig extends CommonGLPI implements PluginSecurityguardConfigConstants
    {
        use PluginSecurityguardConfigBody;

        public static string $rightname = 'config';
    }
} else {
    class PluginSecurityguardConfig extends CommonGLPI implements PluginSecurityguardConfigConstants
    {
        use PluginSecurityguardConfigBody;

        public static $rightname = 'config';
    }
}
