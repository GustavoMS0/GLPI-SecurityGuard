<?php

/**
 * ------------------------------------------------------------------------
 * Security Guard - Camada de compatibilidade GLPI 10 / 11 / 12
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

class PluginSecurityguardCompat
{
    /**
     * Retorna a string de versão do GLPI em execução.
     */
    public static function glpiVersion(): string
    {
        return defined('GLPI_VERSION') ? (string) GLPI_VERSION : '10.0.0';
    }

    /**
     * Retorna a versão principal (major) do GLPI (10, 11, 12...).
     */
    public static function glpiMajor(): int
    {
        $parts = explode('.', self::glpiVersion());
        $major = (int) ($parts[0] ?? 10);
        return $major > 0 ? $major : 10;
    }

    /**
     * Indica se o GLPI é 11.0.0-dev ou superior.
     */
    public static function isGlpi11OrHigher(): bool
    {
        return version_compare(self::glpiVersion(), '11.0.0-dev', '>=');
    }

    /**
     * Verifica se CommonGLPI::$rightname possui declaração de tipo (GLPI 12+).
     */
    public static function typedRightname(): bool
    {
        if (!class_exists('CommonGLPI', true) || !property_exists('CommonGLPI', 'rightname')) {
            return false;
        }
        try {
            $ref = new ReflectionProperty('CommonGLPI', 'rightname');
            return $ref->hasType();
        } catch (ReflectionException $e) {
            return false;
        }
    }

    /**
     * Executa DDL (CREATE/DROP TABLE) compatível com GLPI 10.0.0–10.0.10 (query) e 10.0.11+/11/12 (doQuery).
     *
     * @param object $db
     * @param string $sql
     * @return mixed
     */
    public static function execDdl($db, string $sql)
    {
        if (!is_object($db)) {
            return false;
        }
        if (method_exists($db, 'doQuery')) {
            return $db->doQuery($sql);
        }
        if (method_exists($db, 'query')) {
            return $db->query($sql);
        }
        return false;
    }

    /**
     * Encerra ou lança exceção de acesso negado compatível com GLPI 10/11 e GLPI 12+.
     */
    public static function denyAccess(): void
    {
        if (class_exists('Html') && method_exists('Html', 'displayRightError')) {
            Html::displayRightError();
            return;
        }

        if (class_exists('\\Glpi\\Exception\\Http\\AccessDeniedHttpException')) {
            throw new \Glpi\Exception\Http\AccessDeniedHttpException('Access denied');
        }

        if (!headers_sent()) {
            http_response_code(403);
        }
        exit;
    }

    /**
     * Retorna a URL base web do plugin sem invocar Plugin::getWebDir() (depreciado no 11 e removido no 12).
     * No GLPI 11+, retorna sempre /plugins/securityguard.
     */
    public static function webPath(bool $absolute = false): string
    {
        global $CFG_GLPI;

        $folder = 'plugins';
        if (!self::isGlpi11OrHigher() && basename(dirname(__DIR__, 2)) === 'marketplace') {
            $folder = 'marketplace';
        }

        if ($absolute) {
            $urlBase = '';
            if (isset($CFG_GLPI) && is_array($CFG_GLPI) && isset($CFG_GLPI['url_base'])) {
                $urlBase = rtrim((string) $CFG_GLPI['url_base'], '/');
            }
            if ($urlBase !== '') {
                return $urlBase . '/' . $folder . '/securityguard';
            }
        }

        $rootDoc = '';
        if (isset($CFG_GLPI) && is_array($CFG_GLPI) && isset($CFG_GLPI['root_doc'])) {
            $rootDoc = rtrim((string) $CFG_GLPI['root_doc'], '/');
        }

        return $rootDoc . '/' . $folder . '/securityguard';
    }

    /**
     * Retorna o caminho relativo de ativo estático ('public/' no GLPI < 11 e '' no GLPI >= 11).
     */
    public static function assetPath(string $relative): string
    {
        $clean = ltrim($relative, '/');
        if (strpos($clean, 'public/') === 0) {
            $clean = substr($clean, 7);
        }
        $prefix = self::isGlpi11OrHigher() ? '' : 'public/';
        return $prefix . $clean;
    }

    /**
     * Decodifica entidades HTML no GLPI < 11.0.0-dev sem aplicar stripslashes().
     */
    public static function fromCore(?string $val): string
    {
        if ($val === null || $val === '') {
            return '';
        }
        if (!self::isGlpi11OrHigher()) {
            if (
                class_exists('\\Glpi\\Toolbox\\Sanitizer')
                && method_exists('\\Glpi\\Toolbox\\Sanitizer', 'decodeHtmlSpecialChars')
            ) {
                return (string) \Glpi\Toolbox\Sanitizer::decodeHtmlSpecialChars($val);
            }
            return htmlspecialchars_decode($val, ENT_QUOTES);
        }
        return $val;
    }

    /**
     * Reverte a sanitização global de requisição ($_POST / $input) no GLPI < 11.0.0-dev.
     */
    public static function fromSanitizedInput(?string $val): string
    {
        if ($val === null || $val === '') {
            return '';
        }
        if (!self::isGlpi11OrHigher()) {
            if (
                class_exists('\\Glpi\\Toolbox\\Sanitizer')
                && method_exists('\\Glpi\\Toolbox\\Sanitizer', 'unsanitize')
            ) {
                return (string) \Glpi\Toolbox\Sanitizer::unsanitize($val);
            }
            return self::fromCore(stripslashes($val));
        }
        return $val;
    }

    /**
     * Escapa strings para gravação via $DB->insert() / $DB->update() apenas no GLPI < 11.0.0-dev.
     */
    public static function dbValues(array $data): array
    {
        global $DB;

        if (!self::isGlpi11OrHigher() && isset($DB) && is_object($DB) && method_exists($DB, 'escape')) {
            foreach ($data as $k => $v) {
                if (is_string($v)) {
                    $data[$k] = $DB->escape($v);
                }
            }
        }
        return $data;
    }

    /**
     * Sanitiza dados antes de enviá-los a métodos do núcleo do GLPI < 11.0.0-dev.
     *
     * @param mixed $values
     * @return mixed
     */
    public static function coreInput($values)
    {
        if (!self::isGlpi11OrHigher()) {
            if (class_exists('\\Glpi\\Toolbox\\Sanitizer') && method_exists('\\Glpi\\Toolbox\\Sanitizer', 'sanitize')) {
                return \Glpi\Toolbox\Sanitizer::sanitize($values);
            }
            if (class_exists('Toolbox') && method_exists('Toolbox', 'addslashes_deep')) {
                return Toolbox::addslashes_deep($values);
            }
        }
        return $values;
    }

    /**
     * Valida requisição POST e cabeçalhos de mesma origem (Sec-Fetch-Site, Origin, Referer).
     */
    public static function requireSafePost(): bool
    {
        global $CFG_GLPI;

        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? ''));
        if ($method !== 'POST') {
            return false;
        }

        $secFetchSite = strtolower(trim((string) ($_SERVER['HTTP_SEC_FETCH_SITE'] ?? '')));
        if ($secFetchSite !== '' && $secFetchSite !== 'same-origin') {
            return false;
        }

        $origin  = trim((string) ($_SERVER['HTTP_ORIGIN'] ?? ''));
        $referer = trim((string) ($_SERVER['HTTP_REFERER'] ?? ''));

        $cfg = (isset($CFG_GLPI) && is_array($CFG_GLPI)) ? $CFG_GLPI : [];

        if ($origin !== '') {
            return self::matchesServerOrigin($origin, $cfg);
        }

        if ($referer !== '') {
            return self::matchesServerOrigin($referer, $cfg);
        }

        return true;
    }

    /**
     * Compara esquema, host e porta contra HTTP_HOST e $CFG_GLPI['url_base'].
     */
    private static function matchesServerOrigin(string $url, array $cfgGlpi): bool
    {
        if (strtolower($url) === 'null') {
            return false;
        }

        $originScheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        $originHost   = strtolower((string) parse_url($url, PHP_URL_HOST));
        $originPort   = parse_url($url, PHP_URL_PORT);

        if ($originHost === '' || ($originScheme !== 'http' && $originScheme !== 'https')) {
            return false;
        }

        $defaultOriginPort   = $originScheme === 'https' ? 443 : 80;
        $effectiveOriginPort = $originPort !== null ? (int) $originPort : $defaultOriginPort;

        $rawHttpHost = trim((string) ($_SERVER['HTTP_HOST'] ?? ''));
        if ($rawHttpHost !== '') {
            $parsed = self::splitHostPort($rawHttpHost);
            if ($parsed['host'] !== '' && $originHost === $parsed['host']) {
                if ($parsed['port'] !== null) {
                    if ($effectiveOriginPort === (int) $parsed['port']) {
                        return true;
                    }
                } elseif ($originPort === null || (int) $originPort === $defaultOriginPort) {
                    return true;
                }
            }
        }

        $urlBase = trim((string) ($cfgGlpi['url_base'] ?? ''));
        if ($urlBase !== '') {
            $baseScheme = strtolower((string) parse_url($urlBase, PHP_URL_SCHEME));
            $baseHost   = strtolower((string) parse_url($urlBase, PHP_URL_HOST));
            $basePort   = parse_url($urlBase, PHP_URL_PORT);
            if ($baseHost !== '' && $originHost === $baseHost) {
                $defaultBasePort   = $baseScheme === 'https' ? 443 : ($baseScheme === 'http' ? 80 : null);
                $effectiveBasePort = $basePort !== null ? (int) $basePort : $defaultBasePort;
                if ($effectiveBasePort === null || $effectiveOriginPort === $effectiveBasePort) {
                    return true;
                }
            }
        }

        return false;
    }

    /**
     * Separa host e porta de HTTP_HOST (incluindo IPv6 entre colchetes).
     *
     * @return array{host: string, port: int|null}
     */
    private static function splitHostPort(string $value): array
    {
        $value = strtolower(trim($value));
        if ($value === '') {
            return ['host' => '', 'port' => null];
        }

        if (substr($value, 0, 1) === '[') {
            $end = strpos($value, ']');
            if ($end === false) {
                return ['host' => '', 'port' => null];
            }
            $host = substr($value, 0, $end + 1);
            $rest = substr($value, $end + 1);
            $port = (substr($rest, 0, 1) === ':') ? (int) substr($rest, 1) : null;
            return ['host' => $host, 'port' => ($port !== null && $port > 0) ? $port : null];
        }

        $parts = explode(':', $value);
        $host  = $parts[0] ?? '';
        $port  = isset($parts[1]) && ctype_digit($parts[1]) ? (int) $parts[1] : null;
        return ['host' => $host, 'port' => $port];
    }
}
