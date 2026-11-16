<?php

/**
 * ------------------------------------------------------------------------
 * Security Guard - Proteção contra força bruta e auditoria de segurança
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

class PluginSecurityguardGuard
{
    public const TABLE_LOCKOUTS = 'glpi_plugin_securityguard_lockouts';
    public const TABLE_LOGS     = 'glpi_plugin_securityguard_logs';

    /** @var string|null */
    private static $nowOverride = null;

    /** @var callable|null */
    private static $blockHandler = null;

    /** @var array<string, mixed>|null */
    private static $pendingLogin = null;

    /** @var bool */
    private static $shutdownRegistered = false;

    /**
     * Define timestamp fixo para testes automatizados determinísticos.
     */
    public static function setNowForTest(?string $now): void
    {
        self::$nowOverride = $now;
    }

    /**
     * Permite injetar handler de bloqueio em testes sem encerrar o processo com exit.
     */
    public static function setBlockHandlerForTest(?callable $handler): void
    {
        self::$blockHandler = $handler;
    }

    /**
     * Limpa estado em memória entre testes.
     */
    public static function resetRuntimeState(): void
    {
        self::$nowOverride        = null;
        self::$blockHandler       = null;
        self::$pendingLogin       = null;
        self::$shutdownRegistered = false;
    }

    /**
     * Retorna o timestamp UNIX atual (ou o override de teste).
     */
    public static function nowTimestamp(): int
    {
        if (self::$nowOverride !== null && self::$nowOverride !== '') {
            $parsed = strtotime(self::$nowOverride);
            if ($parsed !== false) {
                return $parsed;
            }
        }
        return time();
    }

    /**
     * Retorna a data/hora atual formatada em SQL.
     */
    public static function nowSql(): string
    {
        return date('Y-m-d H:i:s', self::nowTimestamp());
    }

    /**
     * Cria as tabelas de bloqueios e auditoria do plugin.
     */
    public static function installSchema(): void
    {
        global $DB;

        if (!isset($DB) || !is_object($DB)) {
            return;
        }

        $charset   = 'utf8mb4';
        $collation = 'utf8mb4_unicode_ci';
        if (class_exists('DBConnection')) {
            if (method_exists('DBConnection', 'getDefaultCharset')) {
                $charset = DBConnection::getDefaultCharset();
            }
            if (method_exists('DBConnection', 'getDefaultCollation')) {
                $collation = DBConnection::getDefaultCollation();
            }
        }

        if (!$DB->tableExists(self::TABLE_LOCKOUTS)) {
            $sqlLockouts = 'CREATE TABLE `' . self::TABLE_LOCKOUTS . "` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `scope_key` varchar(128) NOT NULL DEFAULT '',
                `username` varchar(191) NOT NULL DEFAULT '',
                `ip_address` varchar(64) NOT NULL DEFAULT '',
                `attempts` int unsigned NOT NULL DEFAULT '0',
                `first_attempt_at` timestamp NULL DEFAULT NULL,
                `last_attempt_at` timestamp NULL DEFAULT NULL,
                `locked_until` timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                UNIQUE KEY `uniq_scope_key` (`scope_key`),
                KEY `idx_locked_until` (`locked_until`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC";

            PluginSecurityguardCompat::execDdl($DB, $sqlLockouts);
        }

        if (!$DB->tableExists(self::TABLE_LOGS)) {
            $sqlLogs = 'CREATE TABLE `' . self::TABLE_LOGS . "` (
                `id` int unsigned NOT NULL AUTO_INCREMENT,
                `event_type` varchar(64) NOT NULL DEFAULT '',
                `severity` varchar(16) NOT NULL DEFAULT 'info',
                `actor_users_id` int unsigned NOT NULL DEFAULT '0',
                `target_type` varchar(64) NOT NULL DEFAULT '',
                `target_id` int unsigned NOT NULL DEFAULT '0',
                `ip_address` varchar(64) NOT NULL DEFAULT '',
                `summary` varchar(500) NOT NULL DEFAULT '',
                `date_creation` timestamp NULL DEFAULT NULL,
                PRIMARY KEY (`id`),
                KEY `idx_event_type` (`event_type`),
                KEY `idx_date_creation` (`date_creation`)
            ) ENGINE=InnoDB DEFAULT CHARSET={$charset} COLLATE={$collation} ROW_FORMAT=DYNAMIC";

            PluginSecurityguardCompat::execDdl($DB, $sqlLogs);
        }
    }

    /**
     * Remove as tabelas do plugin na desinstalação.
     */
    public static function uninstallSchema(): void
    {
        global $DB;

        if (!isset($DB) || !is_object($DB)) {
            return;
        }

        if ($DB->tableExists(self::TABLE_LOCKOUTS)) {
            PluginSecurityguardCompat::execDdl($DB, 'DROP TABLE IF EXISTS `' . self::TABLE_LOCKOUTS . '`');
        }
        if ($DB->tableExists(self::TABLE_LOGS)) {
            PluginSecurityguardCompat::execDdl($DB, 'DROP TABLE IF EXISTS `' . self::TABLE_LOGS . '`');
        }
    }

    /**
     * Resolve o endereço IP do cliente com proteção contra falsificação de X-Forwarded-For.
     */
    public static function resolveClientIp(): string
    {
        $remoteAddr = trim((string) ($_SERVER['REMOTE_ADDR'] ?? ''));
        if ($remoteAddr === '' || filter_var($remoteAddr, FILTER_VALIDATE_IP) === false) {
            return '0.0.0.0';
        }

        $cfg = PluginSecurityguardConfig::getConfig();
        if ((int) ($cfg['trust_proxy'] ?? 0) !== 1) {
            return $remoteAddr;
        }

        $trustedProxies = (string) ($cfg['trusted_proxies'] ?? '');
        if ($trustedProxies === '' || !PluginSecurityguardConfig::ipMatchesList($remoteAddr, $trustedProxies)) {
            return $remoteAddr;
        }

        $xff = trim((string) ($_SERVER['HTTP_X_FORWARDED_FOR'] ?? ''));
        if ($xff === '') {
            return $remoteAddr;
        }

        $hops = array_map('trim', explode(',', $xff));
        for ($i = count($hops) - 1; $i >= 0; $i--) {
            $hopIp = $hops[$i];
            if ($hopIp === '' || filter_var($hopIp, FILTER_VALIDATE_IP) === false) {
                continue;
            }
            if ($i > 0 && PluginSecurityguardConfig::ipMatchesList($hopIp, $trustedProxies)) {
                continue;
            }
            return $hopIp;
        }

        return $remoteAddr;
    }

    /**
     * Verifica se o IP informado pertence à lista de permissão (allowlist).
     */
    public static function isIpAllowlisted(string $ip): bool
    {
        $cfg       = PluginSecurityguardConfig::getConfig();
        $allowlist = (string) ($cfg['ip_allowlist'] ?? '');
        if ($allowlist === '') {
            return false;
        }
        return PluginSecurityguardConfig::ipMatchesList($ip, $allowlist);
    }

    /**
     * Calcula a chave normalizada do escopo de bloqueio.
     */
    public static function buildScopeKey(string $username, string $ip): string
    {
        $normUser = strtolower(trim($username));
        $normIp   = strtolower(trim($ip));
        if ($normUser !== '') {
            return 'user_ip:' . hash('sha256', $normUser . '|' . $normIp);
        }
        return 'ip:' . $normIp;
    }

    /**
     * Identifica se a requisição atual é uma tentativa de login web ou REST API initSession.
     *
     * @return array{username: string, ip: string, is_api: bool}|null
     */
    public static function detectLoginAttempt(): ?array
    {
        if (function_exists('isCommandLineInterface') && isCommandLineInterface()) {
            return null;
        }

        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $uri    = (string) ($_SERVER['REQUEST_URI'] ?? ($_SERVER['SCRIPT_NAME'] ?? ''));

        // 1. REST API initSession
        if ( stripos($uri, 'apirest.php/initSession') !== false
            || (stripos($uri, 'apirest.php') !== false && stripos($uri, 'initSession') !== false)
        ) {
            $username = '';
            if (!empty($_SERVER['PHP_AUTH_USER'])) {
                $username = (string) $_SERVER['PHP_AUTH_USER'];
            } elseif (!empty($_SERVER['HTTP_AUTHORIZATION'])) {
                $authHeader = trim((string) $_SERVER['HTTP_AUTHORIZATION']);
                if (stripos($authHeader, 'basic ') === 0) {
                    $decoded = base64_decode(substr($authHeader, 6), true);
                    if (is_string($decoded) && strpos($decoded, ':') !== false) {
                        $parts    = explode(':', $decoded, 2);
                        $username = (string) ($parts[0] ?? '');
                    }
                }
            } elseif (!empty($_GET['login'])) {
                $username = (string) $_GET['login'];
            } elseif (!empty($_POST['login'])) {
                $username = (string) $_POST['login'];
            }

            $username = trim(PluginSecurityguardCompat::fromSanitizedInput($username));
            return [
                'username' => substr($username, 0, 191),
                'ip'       => self::resolveClientIp(),
                'is_api'   => true,
            ];
        }

        // 2. Web Login (front/login.php POST)
        if ($method !== 'POST') {
            return null;
        }

        $rawUsername = null;
        if (isset($_POST['login_name']) && is_string($_POST['login_name'])) {
            $rawUsername = $_POST['login_name'];
        } elseif (
            isset($_SESSION['namfield'])
            && is_string($_SESSION['namfield'])
            && $_SESSION['namfield'] !== ''
            && isset($_POST[$_SESSION['namfield']])
            && is_string($_POST[$_SESSION['namfield']])
        ) {
            $rawUsername = $_POST[$_SESSION['namfield']];
        } elseif (stripos($uri, 'login.php') !== false && isset($_POST['name']) && is_string($_POST['name'])) {
            $rawUsername = $_POST['name'];
        }

        if ($rawUsername === null) {
            return null;
        }

        $username = trim(PluginSecurityguardCompat::fromSanitizedInput($rawUsername));
        return [
            'username' => substr($username, 0, 191),
            'ip'       => self::resolveClientIp(),
            'is_api'   => false,
        ];
    }

    /**
     * Hook post_init: verifica se há tentativa de login bloqueada antes de Auth::login().
     */
    public static function onPostInit(): bool
    {
        $cfg = PluginSecurityguardConfig::getConfig();
        if ((int) ($cfg['enabled'] ?? 0) !== 1) {
            return false;
        }

        $attempt = self::detectLoginAttempt();
        if ($attempt === null) {
            return false;
        }

        $username = $attempt['username'];
        $ip       = $attempt['ip'];
        $isApi    = $attempt['is_api'];

        self::$pendingLogin = [
            'username' => $username,
            'ip'       => $ip,
            'is_api'   => $isApi,
            'handled'  => false,
        ];

        if (!self::$shutdownRegistered) {
            register_shutdown_function([self::class, 'evaluateLoginOutcome']);
            self::$shutdownRegistered = true;
        }

        if (self::isIpAllowlisted($ip)) {
            return false;
        }

        $lockoutRow = self::findActiveLockout($username, $ip);
        if ($lockoutRow !== null) {
            self::$pendingLogin['handled'] = true;
            $lockedUntil = (string) ($lockoutRow['locked_until'] ?? '');
            $targetLabel = $username !== '' ? $username : 'anonymous';

            self::recordLog(
                'login_blocked',
                'warning',
                0,
                'User',
                0,
                $ip,
                sprintf(
                    __('Blocked login attempt for "%s" from IP %s (locked until %s).', 'securityguard'),
                    $targetLabel,
                    $ip,
                    $lockedUntil
                )
            );

            self::blockCurrentLoginAttempt($username, $ip, $isApi, $lockedUntil);
            return true;
        }

        return false;
    }

    /**
     * Hook init_session: executado quando o login tem sucesso. Limpa falhas e registra login_success.
     */
    public static function onInitSession(): void
    {
        $cfg = PluginSecurityguardConfig::getConfig();
        if ((int) ($cfg['enabled'] ?? 0) !== 1) {
            return;
        }

        $username = '';
        $ip       = '';
        if (is_array(self::$pendingLogin)) {
            $username = (string) (self::$pendingLogin['username'] ?? '');
            $ip       = (string) (self::$pendingLogin['ip'] ?? '');
            self::$pendingLogin['handled'] = true;
        }

        if ($username === '' && !empty($_SESSION['glpiname']) && is_string($_SESSION['glpiname'])) {
            $username = trim($_SESSION['glpiname']);
        }
        if ($ip === '') {
            $ip = self::resolveClientIp();
        }

        self::clearLockoutFor($username, $ip);

        if ((int) ($cfg['audit_logins'] ?? 0) === 1) {
            $userId = 0;
            if (class_exists('Session') && method_exists('Session', 'getLoginUserID')) {
                $uid    = Session::getLoginUserID(true);
                $userId = is_numeric($uid) ? (int) $uid : 0;
            }
            $label = $username !== '' ? $username : ('#' . $userId);
            self::recordLog(
                'login_success',
                'info',
                $userId,
                'User',
                $userId,
                $ip,
                sprintf(__('Successful authentication for user "%s" from IP %s.', 'securityguard'), $label, $ip)
            );
        }
    }

    /**
     * Avalia o desfecho da requisição de login (registrado via register_shutdown_function e invocável em testes).
     */
    public static function evaluateLoginOutcome(): void
    {
        if (!is_array(self::$pendingLogin) || !empty(self::$pendingLogin['handled'])) {
            return;
        }

        self::$pendingLogin['handled'] = true;

        $cfg = PluginSecurityguardConfig::getConfig();
        if ((int) ($cfg['enabled'] ?? 0) !== 1) {
            return;
        }

        $loggedUserId = 0;
        if (class_exists('Session') && method_exists('Session', 'getLoginUserID')) {
            $uid          = Session::getLoginUserID(true);
            $loggedUserId = is_numeric($uid) ? (int) $uid : 0;
        }

        if ($loggedUserId > 0 || !empty($_SESSION['mfa_pre_auth'])) {
            return;
        }

        $username = (string) (self::$pendingLogin['username'] ?? '');
        $ip       = (string) (self::$pendingLogin['ip'] ?? self::resolveClientIp());

        if (self::isIpAllowlisted($ip)) {
            if ((int) ($cfg['audit_logins'] ?? 0) === 1) {
                $label = $username !== '' ? $username : 'anonymous';
                self::recordLog(
                    'login_failed',
                    'warning',
                    0,
                    'User',
                    0,
                    $ip,
                    sprintf(__('Failed login attempt for "%s" from allowlisted IP %s.', 'securityguard'), $label, $ip)
                );
            }
            return;
        }

        self::recordFailedAttempt($username, $ip);
    }

    /**
     * Registra uma falha de autenticação na janela configurada e aplica bloqueio ao atingir max_attempts.
     */
    public static function recordFailedAttempt(string $username, string $ip): array
    {
        global $DB;

        $cfg            = PluginSecurityguardConfig::getConfig();
        $maxAttempts    = (int) ($cfg['max_attempts'] ?? 5);
        $windowMinutes  = (int) ($cfg['window_minutes'] ?? 15);
        $lockoutMinutes = (int) ($cfg['lockout_minutes'] ?? 15);
        $auditLogins    = (int) ($cfg['audit_logins'] ?? 1);

        $scopeKey = self::buildScopeKey($username, $ip);
        $nowTs    = self::nowTimestamp();
        $nowSql   = self::nowSql();

        $existing = self::getLockoutRowByScope($scopeKey);
        $attempts = 1;
        $firstAt  = $nowSql;

        if ($existing !== null) {
            $prevFirstTs = !empty($existing['first_attempt_at']) ? strtotime((string) $existing['first_attempt_at']) : false;
            $withinWin   = ($prevFirstTs !== false && ($nowTs - $prevFirstTs) <= ($windowMinutes * 60));
            if ($withinWin) {
                $attempts = (int) ($existing['attempts'] ?? 0) + 1;
                $firstAt  = (string) $existing['first_attempt_at'];
            }
        }

        $lockedUntil = null;
        $triggered   = false;
        if ($attempts >= $maxAttempts) {
            $lockedUntil = date('Y-m-d H:i:s', $nowTs + ($lockoutMinutes * 60));
            $triggered   = true;
        }

        $rowValues = [
            'scope_key'        => $scopeKey,
            'username'         => substr(trim($username), 0, 191),
            'ip_address'       => substr(trim($ip), 0, 64),
            'attempts'         => $attempts,
            'first_attempt_at' => $firstAt,
            'last_attempt_at'  => $nowSql,
            'locked_until'     => $lockedUntil,
        ];

        if (isset($DB) && is_object($DB) && $DB->tableExists(self::TABLE_LOCKOUTS)) {
            $dbData = PluginSecurityguardCompat::dbValues($rowValues);
            if ($existing !== null) {
                $DB->update(self::TABLE_LOCKOUTS, $dbData, ['id' => (int) $existing['id']]);
            } else {
                $DB->insert(self::TABLE_LOCKOUTS, $dbData);
            }
        }

        $label = $username !== '' ? $username : 'anonymous';
        if ($triggered) {
            self::recordLog(
                'lockout_triggered',
                'critical',
                0,
                'User',
                0,
                $ip,
                sprintf(
                    __('Lockout triggered for "%s" from IP %s after %d failed attempts (locked until %s).', 'securityguard'),
                    $label,
                    $ip,
                    $attempts,
                    (string) $lockedUntil
                )
            );
        } elseif ($auditLogins === 1) {
            self::recordLog(
                'login_failed',
                'warning',
                0,
                'User',
                0,
                $ip,
                sprintf(
                    __('Failed login attempt (%d/%d) for "%s" from IP %s.', 'securityguard'),
                    $attempts,
                    $maxAttempts,
                    $label,
                    $ip
                )
            );
        }

        return $rowValues;
    }

    /**
     * Busca bloqueio ativo para o par (username, ip) ou para o IP isolado.
     *
     * @return array<string, mixed>|null
     */
    public static function findActiveLockout(string $username, string $ip): ?array
    {
        $nowTs  = self::nowTimestamp();
        $scopes = [];
        if (trim($username) !== '') {
            $scopes[] = self::buildScopeKey($username, $ip);
        }
        $scopes[] = self::buildScopeKey('', $ip);

        foreach ($scopes as $scopeKey) {
            $row = self::getLockoutRowByScope($scopeKey);
            if ($row !== null && !empty($row['locked_until'])) {
                $untilTs = strtotime((string) $row['locked_until']);
                if ($untilTs !== false && $untilTs > $nowTs) {
                    return $row;
                }
            }
        }

        return null;
    }

    /**
     * Limpa falhas acumuladas para o par (username, ip) após autenticação bem-sucedida.
     */
    public static function clearLockoutFor(string $username, string $ip): void
    {
        global $DB;

        if (!isset($DB) || !is_object($DB) || !$DB->tableExists(self::TABLE_LOCKOUTS)) {
            return;
        }

        $scopes = [self::buildScopeKey('', $ip)];
        if (trim($username) !== '') {
            $scopes[] = self::buildScopeKey($username, $ip);
        }

        foreach ($scopes as $scopeKey) {
            $DB->delete(self::TABLE_LOCKOUTS, ['scope_key' => $scopeKey]);
        }
    }

    /**
     * Desbloqueia manualmente um registro de bloqueio pelo ID.
     */
    public static function unlockById(int $id): bool
    {
        global $DB;

        if ($id <= 0 || !isset($DB) || !is_object($DB) || !$DB->tableExists(self::TABLE_LOCKOUTS)) {
            return false;
        }

        $targetRow = null;
        foreach ($DB->request(['FROM' => self::TABLE_LOCKOUTS, 'WHERE' => ['id' => $id], 'LIMIT' => 1]) as $row) {
            $targetRow = $row;
            break;
        }

        if ($targetRow === null) {
            return false;
        }

        $DB->delete(self::TABLE_LOCKOUTS, ['id' => $id]);

        $actorId = 0;
        if (class_exists('Session') && method_exists('Session', 'getLoginUserID')) {
            $uid     = Session::getLoginUserID(true);
            $actorId = is_numeric($uid) ? (int) $uid : 0;
        }

        $userLabel = (string) ($targetRow['username'] ?? '');
        $ipLabel   = (string) ($targetRow['ip_address'] ?? '');
        self::recordLog(
            'lockout_unlocked',
            'info',
            $actorId,
            'Lockout',
            $id,
            self::resolveClientIp(),
            sprintf(
                __('Manual unlock executed for user "%s" / IP %s.', 'securityguard'),
                $userLabel !== '' ? $userLabel : 'anonymous',
                $ipLabel
            )
        );

        return true;
    }

    /**
     * Hook item_add para Profile_User e User.
     *
     * @param mixed $item
     */
    public static function onItemAdd($item): void
    {
        if (!self::shouldAuditChanges() || !is_object($item)) {
            return;
        }

        $actorId = self::currentActorId();
        $ip      = self::resolveClientIp();

        if ($item instanceof Profile_User) {
            $usersId    = (int) ($item->fields['users_id'] ?? ($item->input['users_id'] ?? 0));
            $profilesId = (int) ($item->fields['profiles_id'] ?? ($item->input['profiles_id'] ?? 0));
            $entitiesId = (int) ($item->fields['entities_id'] ?? ($item->input['entities_id'] ?? 0));
            $isHighPriv = self::isHighPrivilegeProfile($profilesId);
            $severity   = $isHighPriv ? 'critical' : 'warning';

            $summary = $isHighPriv
                ? sprintf(
                    __('High-privilege profile #%d (config:UPDATE) assigned to user #%d in entity #%d.', 'securityguard'),
                    $profilesId,
                    $usersId,
                    $entitiesId
                )
                : sprintf(
                    __('Profile #%d assigned to user #%d in entity #%d.', 'securityguard'),
                    $profilesId,
                    $usersId,
                    $entitiesId
                );

            self::recordLog('profile_assigned', $severity, $actorId, 'User', $usersId, $ip, $summary);
            return;
        }

        if ($item instanceof User) {
            $userId   = (int) ($item->fields['id'] ?? 0);
            $userName = (string) ($item->fields['name'] ?? ($item->input['name'] ?? ''));
            $userName = PluginSecurityguardCompat::fromCore($userName);

            self::recordLog(
                'user_created',
                'info',
                $actorId,
                'User',
                $userId,
                $ip,
                sprintf(__('User account "%s" (#%d) created.', 'securityguard'), $userName, $userId)
            );
        }
    }

    /**
     * Hook item_update para User (monitora senha, tokens e status sem jamais gravar segredos).
     *
     * @param mixed $item
     */
    public static function onItemUpdate($item): void
    {
        if (!self::shouldAuditChanges() || !($item instanceof User)) {
            return;
        }

        $userId   = (int) ($item->fields['id'] ?? ($item->input['id'] ?? 0));
        $userName = (string) ($item->fields['name'] ?? ($item->input['name'] ?? ('#' . $userId)));
        $userName = PluginSecurityguardCompat::fromCore($userName);
        $actorId  = self::currentActorId();
        $ip       = self::resolveClientIp();

        $updates   = (isset($item->updates) && is_array($item->updates)) ? $item->updates : [];
        $input     = (isset($item->input) && is_array($item->input)) ? $item->input : [];
        $oldvalues = (isset($item->oldvalues) && is_array($item->oldvalues)) ? $item->oldvalues : [];

        // 1. Alteração de senha (nunca logar o hash ou valor!)
        $passwordChanged = in_array('password', $updates, true)
            || (!empty($input['password']) && array_key_exists('password', $oldvalues))
            || (!empty($input['password']) && empty($updates));

        if ($passwordChanged) {
            self::recordLog(
                'password_changed',
                'warning',
                $actorId,
                'User',
                $userId,
                $ip,
                sprintf(__('Password updated for user "%s" (#%d).', 'securityguard'), $userName, $userId)
            );
        }

        // 2. Rotação de personal_token / api_token (nunca logar o valor do token!)
        $tokenChanged = in_array('personal_token', $updates, true)
            || in_array('api_token', $updates, true)
            || (!empty($input['personal_token']) && empty($updates))
            || (!empty($input['api_token']) && empty($updates));

        if ($tokenChanged) {
            self::recordLog(
                'token_changed',
                'warning',
                $actorId,
                'User',
                $userId,
                $ip,
                sprintf(__('API or personal token rotated for user "%s" (#%d).', 'securityguard'), $userName, $userId)
            );
        }

        // 3. Mudança de status (is_active / is_deleted)
        $activeChanged  = in_array('is_active', $updates, true) || array_key_exists('is_active', $oldvalues);
        $deletedChanged = in_array('is_deleted', $updates, true) || array_key_exists('is_deleted', $oldvalues);

        if ($activeChanged || $deletedChanged) {
            $isActive  = (int) ($item->fields['is_active'] ?? ($input['is_active'] ?? 1));
            $isDeleted = (int) ($item->fields['is_deleted'] ?? ($input['is_deleted'] ?? 0));
            self::recordLog(
                'user_status_changed',
                'warning',
                $actorId,
                'User',
                $userId,
                $ip,
                sprintf(
                    __('Status changed for user "%s" (#%d): is_active=%d, is_deleted=%d.', 'securityguard'),
                    $userName,
                    $userId,
                    $isActive,
                    $isDeleted
                )
            );
        }
    }

    /**
     * Hook item_delete para Profile_User e User.
     *
     * @param mixed $item
     */
    public static function onItemDelete($item): void
    {
        if (!self::shouldAuditChanges() || !is_object($item)) {
            return;
        }

        $actorId = self::currentActorId();
        $ip      = self::resolveClientIp();

        if ($item instanceof Profile_User) {
            $usersId    = (int) ($item->fields['users_id'] ?? ($item->input['users_id'] ?? 0));
            $profilesId = (int) ($item->fields['profiles_id'] ?? ($item->input['profiles_id'] ?? 0));
            self::recordLog(
                'profile_removed',
                'warning',
                $actorId,
                'User',
                $usersId,
                $ip,
                sprintf(__('Profile #%d removed from user #%d.', 'securityguard'), $profilesId, $usersId)
            );
            return;
        }

        if ($item instanceof User) {
            $userId   = (int) ($item->fields['id'] ?? 0);
            $userName = PluginSecurityguardCompat::fromCore((string) ($item->fields['name'] ?? ('#' . $userId)));
            self::recordLog(
                'user_status_changed',
                'warning',
                $actorId,
                'User',
                $userId,
                $ip,
                sprintf(__('User account "%s" (#%d) moved to trash (is_deleted=1).', 'securityguard'), $userName, $userId)
            );
        }
    }

    /**
     * Hook item_purge para Profile_User e User.
     *
     * @param mixed $item
     */
    public static function onItemPurge($item): void
    {
        if (!self::shouldAuditChanges() || !is_object($item)) {
            return;
        }

        $actorId = self::currentActorId();
        $ip      = self::resolveClientIp();

        if ($item instanceof Profile_User) {
            $usersId    = (int) ($item->fields['users_id'] ?? ($item->input['users_id'] ?? 0));
            $profilesId = (int) ($item->fields['profiles_id'] ?? ($item->input['profiles_id'] ?? 0));
            self::recordLog(
                'profile_removed',
                'warning',
                $actorId,
                'User',
                $usersId,
                $ip,
                sprintf(__('Profile #%d removed from user #%d.', 'securityguard'), $profilesId, $usersId)
            );
            return;
        }

        if ($item instanceof User) {
            $userId   = (int) ($item->fields['id'] ?? 0);
            $userName = PluginSecurityguardCompat::fromCore((string) ($item->fields['name'] ?? ('#' . $userId)));
            self::recordLog(
                'user_purged',
                'critical',
                $actorId,
                'User',
                $userId,
                $ip,
                sprintf(__('User account "%s" (#%d) permanently purged.', 'securityguard'), $userName, $userId)
            );
        }
    }

    /**
     * Grava um evento de auditoria na tabela glpi_plugin_securityguard_logs.
     */
    public static function recordLog(
        string $eventType,
        string $severity,
        int $actorUsersId,
        string $targetType,
        int $targetId,
        string $ipAddress,
        string $summary
    ): bool {
        global $DB;

        if (!isset($DB) || !is_object($DB) || !$DB->tableExists(self::TABLE_LOGS)) {
            return false;
        }

        $allowedSeverities = ['info', 'warning', 'critical'];
        $cleanSeverity     = in_array($severity, $allowedSeverities, true) ? $severity : 'info';

        $row = [
            'event_type'     => substr(trim($eventType), 0, 64),
            'severity'       => $cleanSeverity,
            'actor_users_id' => max(0, $actorUsersId),
            'target_type'    => substr(trim($targetType), 0, 64),
            'target_id'      => max(0, $targetId),
            'ip_address'     => substr(trim($ipAddress), 0, 64),
            'summary'        => substr(trim($summary), 0, 500),
            'date_creation'  => self::nowSql(),
        ];

        return (bool) $DB->insert(self::TABLE_LOGS, PluginSecurityguardCompat::dbValues($row));
    }

    /**
     * Remove logs anteriores ao período de retenção e bloqueios já expirados.
     */
    public static function purgeOldLogs(?int $retentionDays = null): int
    {
        global $DB;

        if (!isset($DB) || !is_object($DB)) {
            return 0;
        }

        if ($retentionDays === null) {
            $cfg           = PluginSecurityguardConfig::getConfig();
            $retentionDays = (int) ($cfg['retention_days'] ?? 90);
        }
        $retentionDays = max(1, min(3650, $retentionDays));

        $cutoffTs = self::nowTimestamp() - ($retentionDays * 86400);
        $nowTs    = self::nowTimestamp();
        $deleted  = 0;

        if ($DB->tableExists(self::TABLE_LOGS)) {
            $toDeleteIds = [];
            foreach ($DB->request(['FROM' => self::TABLE_LOGS]) as $row) {
                $createdStr = (string) ($row['date_creation'] ?? '');
                $createdTs  = $createdStr !== '' ? strtotime($createdStr) : false;
                if ($createdTs !== false && $createdTs < $cutoffTs) {
                    $toDeleteIds[] = (int) ($row['id'] ?? 0);
                }
            }
            foreach ($toDeleteIds as $id) {
                if ($id > 0) {
                    $DB->delete(self::TABLE_LOGS, ['id' => $id]);
                    $deleted++;
                }
            }
        }

        if ($DB->tableExists(self::TABLE_LOCKOUTS)) {
            $expiredIds = [];
            foreach ($DB->request(['FROM' => self::TABLE_LOCKOUTS]) as $row) {
                $lockedStr = (string) ($row['locked_until'] ?? '');
                if ($lockedStr !== '') {
                    $lockedTs = strtotime($lockedStr);
                    if ($lockedTs !== false && $lockedTs <= $nowTs) {
                        $expiredIds[] = (int) ($row['id'] ?? 0);
                    }
                }
            }
            foreach ($expiredIds as $id) {
                if ($id > 0) {
                    $DB->delete(self::TABLE_LOCKOUTS, ['id' => $id]);
                }
            }
        }

        return $deleted;
    }

    /**
     * Lista os bloqueios ativos ordenados por locked_until DESC.
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getActiveLockouts(): array
    {
        global $DB;

        if (!isset($DB) || !is_object($DB) || !$DB->tableExists(self::TABLE_LOCKOUTS)) {
            return [];
        }

        $nowTs  = self::nowTimestamp();
        $result = [];

        foreach ($DB->request(['FROM' => self::TABLE_LOCKOUTS, 'ORDER' => 'id DESC']) as $row) {
            $untilStr = (string) ($row['locked_until'] ?? '');
            if ($untilStr === '') {
                continue;
            }
            $untilTs = strtotime($untilStr);
            if ($untilTs !== false && $untilTs > $nowTs) {
                $row['username']   = PluginSecurityguardCompat::fromCore((string) ($row['username'] ?? ''));
                $row['ip_address'] = PluginSecurityguardCompat::fromCore((string) ($row['ip_address'] ?? ''));
                $result[]          = $row;
            }
        }

        return $result;
    }

    /**
     * Lista os eventos de auditoria mais recentes (padrão 100).
     *
     * @return array<int, array<string, mixed>>
     */
    public static function getRecentLogs(int $limit = 100): array
    {
        global $DB;

        if (!isset($DB) || !is_object($DB) || !$DB->tableExists(self::TABLE_LOGS)) {
            return [];
        }

        $limit = max(1, min(500, $limit));
        $rows  = [];

        $it = $DB->request([
            'FROM'  => self::TABLE_LOGS,
            'ORDER' => 'id DESC',
            'LIMIT' => $limit,
        ]);

        foreach ($it as $row) {
            $row['event_type']  = PluginSecurityguardCompat::fromCore((string) ($row['event_type'] ?? ''));
            $row['severity']    = PluginSecurityguardCompat::fromCore((string) ($row['severity'] ?? 'info'));
            $row['target_type'] = PluginSecurityguardCompat::fromCore((string) ($row['target_type'] ?? ''));
            $row['ip_address']  = PluginSecurityguardCompat::fromCore((string) ($row['ip_address'] ?? ''));
            $row['summary']     = PluginSecurityguardCompat::fromCore((string) ($row['summary'] ?? ''));
            $rows[]             = $row;
        }

        return $rows;
    }

    /**
     * Busca linha de bloqueio por scope_key.
     *
     * @return array<string, mixed>|null
     */
    private static function getLockoutRowByScope(string $scopeKey): ?array
    {
        global $DB;

        if (!isset($DB) || !is_object($DB) || !$DB->tableExists(self::TABLE_LOCKOUTS)) {
            return null;
        }

        $it = $DB->request([
            'FROM'  => self::TABLE_LOCKOUTS,
            'WHERE' => ['scope_key' => $scopeKey],
            'LIMIT' => 1,
        ]);

        foreach ($it as $row) {
            return $row;
        }

        return null;
    }

    /**
     * Interrompe a tentativa de login bloqueada (HTTP 429 JSON na API ou mensagem + redirect na Web).
     */
    private static function blockCurrentLoginAttempt(string $username, string $ip, bool $isApi, string $lockedUntil): void
    {
        $msg = __('Too many failed login attempts. Please try again later.', 'securityguard');

        if (self::$blockHandler !== null) {
            call_user_func(self::$blockHandler, [
                'blocked'      => true,
                'username'     => $username,
                'ip'           => $ip,
                'is_api'       => $isApi,
                'status'       => $isApi ? 429 : 302,
                'message'      => $msg,
                'locked_until' => $lockedUntil,
            ]);
            return;
        }

        if ($isApi) {
            if (!headers_sent()) {
                http_response_code(429);
                header('Content-Type: application/json; charset=UTF-8');
                header('Retry-After: 60');
            }
            echo json_encode(['ERROR_LOCKED_OUT', $msg]);
            exit;
        }

        if (class_exists('Session') && method_exists('Session', 'addMessageAfterRedirect')) {
            $errConst = defined('ERROR') ? ERROR : 3;
            Session::addMessageAfterRedirect($msg, false, $errConst);
        }

        global $CFG_GLPI;
        $rootDoc = (isset($CFG_GLPI) && is_array($CFG_GLPI) && isset($CFG_GLPI['root_doc']))
            ? rtrim((string) $CFG_GLPI['root_doc'], '/')
            : '';

        if (class_exists('Html') && method_exists('Html', 'redirect')) {
            Html::redirect($rootDoc . '/front/login.php');
        }
        exit;
    }

    private static function shouldAuditChanges(): bool
    {
        $cfg = PluginSecurityguardConfig::getConfig();
        return ((int) ($cfg['enabled'] ?? 0) === 1 && (int) ($cfg['audit_changes'] ?? 0) === 1);
    }

    private static function currentActorId(): int
    {
        if (class_exists('Session') && method_exists('Session', 'getLoginUserID')) {
            $uid = Session::getLoginUserID(true);
            if (is_numeric($uid) && (int) $uid > 0) {
                return (int) $uid;
            }
        }
        return 0;
    }

    /**
     * Verifica se o perfil possui permissão administrativa config:UPDATE.
     */
    private static function isHighPrivilegeProfile(int $profilesId): bool
    {
        global $DB;

        if ($profilesId <= 0 || !isset($DB) || !is_object($DB) || !$DB->tableExists('glpi_profilerights')) {
            return false;
        }

        $updateBit = defined('UPDATE') ? (int) UPDATE : 2;
        $it        = $DB->request([
            'FROM'  => 'glpi_profilerights',
            'WHERE' => [
                'profiles_id' => $profilesId,
                'name'        => 'config',
            ],
            'LIMIT' => 1,
        ]);

        foreach ($it as $row) {
            $rights = (int) ($row['rights'] ?? 0);
            if (($rights & $updateBit) === $updateBit) {
                return true;
            }
        }

        return false;
    }
}
