<?php

/**
 * ------------------------------------------------------------------------
 * Security Guard - Painel administrativo de configuração e auditoria
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
    include_once __DIR__ . '/../../../inc/includes.php';
}

require_once __DIR__ . '/../setup.php';

$requestMethod = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));

if ($requestMethod === 'POST') {
    Session::checkRight('config', UPDATE);
    if (!PluginSecurityguardCompat::requireSafePost()) {
        PluginSecurityguardCompat::denyAccess();
        return;
    }

    if (!empty($_POST['unlock_id'])) {
        $unlockId = (int) $_POST['unlock_id'];
        if (PluginSecurityguardGuard::unlockById($unlockId)) {
            Session::addMessageAfterRedirect(
                __('Lockout entry unlocked successfully.', 'securityguard'),
                false,
                defined('INFO') ? INFO : 0
            );
        }
        Html::back();
        return;
    }

    if (!empty($_POST['purge_logs'])) {
        $purged = PluginSecurityguardGuard::purgeOldLogs();
        Session::addMessageAfterRedirect(
            sprintf(__('Purged %d expired audit log entries.', 'securityguard'), $purged),
            false,
            defined('INFO') ? INFO : 0
        );
        Html::back();
        return;
    }

    if (!empty($_POST['update'])) {
        PluginSecurityguardConfig::saveConfig([
            'enabled'         => isset($_POST['enabled']) ? (int) $_POST['enabled'] : 0,
            'max_attempts'    => $_POST['max_attempts'] ?? 5,
            'window_minutes'  => $_POST['window_minutes'] ?? 15,
            'lockout_minutes' => $_POST['lockout_minutes'] ?? 15,
            'trust_proxy'     => isset($_POST['trust_proxy']) ? (int) $_POST['trust_proxy'] : 0,
            'trusted_proxies' => (string) ($_POST['trusted_proxies'] ?? ''),
            'ip_allowlist'    => (string) ($_POST['ip_allowlist'] ?? ''),
            'audit_logins'    => isset($_POST['audit_logins']) ? (int) $_POST['audit_logins'] : 0,
            'audit_changes'   => isset($_POST['audit_changes']) ? (int) $_POST['audit_changes'] : 0,
            'retention_days'  => $_POST['retention_days'] ?? 90,
        ]);

        Session::addMessageAfterRedirect(
            __('Security Guard configuration saved successfully.', 'securityguard'),
            false,
            defined('INFO') ? INFO : 0
        );
        Html::back();
        return;
    }
}

Session::checkRight('config', READ);

$config   = PluginSecurityguardConfig::getConfig();
$canEdit  = Session::haveRight('config', UPDATE);
$formUrl  = PluginSecurityguardCompat::webPath() . '/front/config.form.php';
$lockouts = PluginSecurityguardGuard::getActiveLockouts();
$logs     = PluginSecurityguardGuard::getRecentLogs(100);

Html::header(
    __('Security Guard', 'securityguard'),
    (string) ($_SERVER['PHP_SELF'] ?? $formUrl),
    'config',
    'plugins'
);

$esc = static function ($value): string {
    return htmlspecialchars((string) $value, ENT_QUOTES, 'UTF-8');
};

echo '<div class="sg-container">';

// 1. Formulário de Configuração
echo '<div class="sg-card">';
echo '<h2 class="sg-card-title">' . $esc(__('Brute-Force Protection & Audit Policy', 'securityguard')) . '</h2>';
echo '<form method="post" action="' . $esc($formUrl) . '">';
echo '<div class="sg-grid">';

echo '<div class="sg-field">';
echo '<label for="sg_enabled">' . $esc(__('Enable protection and auditing', 'securityguard')) . '</label>';
echo '<select id="sg_enabled" name="enabled"' . ($canEdit ? '' : ' disabled') . '>';
echo '<option value="1"' . ((int) $config['enabled'] === 1 ? ' selected' : '') . '>' . $esc(__('Yes', 'securityguard')) . '</option>';
echo '<option value="0"' . ((int) $config['enabled'] === 0 ? ' selected' : '') . '>' . $esc(__('No', 'securityguard')) . '</option>';
echo '</select>';
echo '</div>';

echo '<div class="sg-field">';
echo '<label for="sg_max_attempts">' . $esc(__('Max failed attempts before lockout (3-50)', 'securityguard')) . '</label>';
echo '<input type="number" id="sg_max_attempts" name="max_attempts" min="3" max="50" value="' . $esc($config['max_attempts']) . '"' . ($canEdit ? '' : ' readonly') . '>';
echo '</div>';

echo '<div class="sg-field">';
echo '<label for="sg_window_minutes">' . $esc(__('Failure observation window (minutes)', 'securityguard')) . '</label>';
echo '<input type="number" id="sg_window_minutes" name="window_minutes" min="1" max="1440" value="' . $esc($config['window_minutes']) . '"' . ($canEdit ? '' : ' readonly') . '>';
echo '</div>';

echo '<div class="sg-field">';
echo '<label for="sg_lockout_minutes">' . $esc(__('Lockout duration (minutes)', 'securityguard')) . '</label>';
echo '<input type="number" id="sg_lockout_minutes" name="lockout_minutes" min="1" max="1440" value="' . $esc($config['lockout_minutes']) . '"' . ($canEdit ? '' : ' readonly') . '>';
echo '</div>';

echo '<div class="sg-field">';
echo '<label for="sg_trust_proxy">' . $esc(__('Honor X-Forwarded-For from trusted proxies', 'securityguard')) . '</label>';
echo '<select id="sg_trust_proxy" name="trust_proxy"' . ($canEdit ? '' : ' disabled') . '>';
echo '<option value="0"' . ((int) $config['trust_proxy'] === 0 ? ' selected' : '') . '>' . $esc(__('No', 'securityguard')) . '</option>';
echo '<option value="1"' . ((int) $config['trust_proxy'] === 1 ? ' selected' : '') . '>' . $esc(__('Yes', 'securityguard')) . '</option>';
echo '</select>';
echo '</div>';

echo '<div class="sg-field">';
echo '<label for="sg_trusted_proxies">' . $esc(__('Trusted proxy IPs / CIDRs (comma-separated)', 'securityguard')) . '</label>';
echo '<input type="text" id="sg_trusted_proxies" name="trusted_proxies" value="' . $esc($config['trusted_proxies']) . '" placeholder="10.0.0.1, 172.16.0.0/12"' . ($canEdit ? '' : ' readonly') . '>';
echo '</div>';

echo '<div class="sg-field sg-field-wide">';
echo '<label for="sg_ip_allowlist">' . $esc(__('Allowlisted IPs / CIDRs (never locked out)', 'securityguard')) . '</label>';
echo '<input type="text" id="sg_ip_allowlist" name="ip_allowlist" value="' . $esc($config['ip_allowlist']) . '" placeholder="127.0.0.1, ::1"' . ($canEdit ? '' : ' readonly') . '>';
echo '</div>';

echo '<div class="sg-field">';
echo '<label for="sg_audit_logins">' . $esc(__('Audit login successes and failures', 'securityguard')) . '</label>';
echo '<select id="sg_audit_logins" name="audit_logins"' . ($canEdit ? '' : ' disabled') . '>';
echo '<option value="1"' . ((int) $config['audit_logins'] === 1 ? ' selected' : '') . '>' . $esc(__('Yes', 'securityguard')) . '</option>';
echo '<option value="0"' . ((int) $config['audit_logins'] === 0 ? ' selected' : '') . '>' . $esc(__('No', 'securityguard')) . '</option>';
echo '</select>';
echo '</div>';

echo '<div class="sg-field">';
echo '<label for="sg_audit_changes">' . $esc(__('Audit user and profile privilege changes', 'securityguard')) . '</label>';
echo '<select id="sg_audit_changes" name="audit_changes"' . ($canEdit ? '' : ' disabled') . '>';
echo '<option value="1"' . ((int) $config['audit_changes'] === 1 ? ' selected' : '') . '>' . $esc(__('Yes', 'securityguard')) . '</option>';
echo '<option value="0"' . ((int) $config['audit_changes'] === 0 ? ' selected' : '') . '>' . $esc(__('No', 'securityguard')) . '</option>';
echo '</select>';
echo '</div>';

echo '<div class="sg-field">';
echo '<label for="sg_retention_days">' . $esc(__('Audit log retention (days)', 'securityguard')) . '</label>';
echo '<input type="number" id="sg_retention_days" name="retention_days" min="1" max="3650" value="' . $esc($config['retention_days']) . '"' . ($canEdit ? '' : ' readonly') . '>';
echo '</div>';

echo '</div>';

if ($canEdit) {
    echo '<div class="sg-actions">';
    echo '<button type="submit" name="update" value="1" class="btn btn-primary sg-btn">' . $esc(__('Save settings', 'securityguard')) . '</button>';
    echo '</div>';
}

Html::closeForm();
echo '</div>';

// 2. Bloqueios Ativos
echo '<div class="sg-card">';
echo '<h3 class="sg-card-title">' . $esc(__('Active Lockouts', 'securityguard')) . ' (' . count($lockouts) . ')</h3>';
if ($lockouts === []) {
    echo '<p class="sg-empty">' . $esc(__('No active lockouts at the moment.', 'securityguard')) . '</p>';
} else {
    echo '<div class="sg-table-wrap"><table class="sg-table">';
    echo '<thead><tr>';
    echo '<th>' . $esc(__('Username', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('IP Address', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('Failed Attempts', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('Last Attempt', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('Locked Until', 'securityguard')) . '</th>';
    if ($canEdit) {
        echo '<th>' . $esc(__('Actions', 'securityguard')) . '</th>';
    }
    echo '</tr></thead><tbody>';

    foreach ($lockouts as $lockRow) {
        $lockId = (int) ($lockRow['id'] ?? 0);
        echo '<tr>';
        echo '<td>' . $esc($lockRow['username'] !== '' ? $lockRow['username'] : '-') . '</td>';
        echo '<td><code>' . $esc($lockRow['ip_address'] ?? '') . '</code></td>';
        echo '<td>' . (int) ($lockRow['attempts'] ?? 0) . '</td>';
        echo '<td>' . $esc($lockRow['last_attempt_at'] ?? '') . '</td>';
        echo '<td><span class="sg-badge sg-badge-critical">' . $esc($lockRow['locked_until'] ?? '') . '</span></td>';
        if ($canEdit) {
            echo '<td>';
            echo '<form method="post" action="' . $esc($formUrl) . '" class="sg-inline-form">';
            echo '<input type="hidden" name="unlock_id" value="' . $lockId . '">';
            echo '<button type="submit" class="btn btn-sm btn-outline-secondary sg-btn-sm">' . $esc(__('Unlock', 'securityguard')) . '</button>';
            Html::closeForm();
            echo '</td>';
        }
        echo '</tr>';
    }

    echo '</tbody></table></div>';
}
echo '</div>';

// 3. Últimos 100 Eventos de Auditoria
echo '<div class="sg-card">';
echo '<div class="sg-card-header">';
echo '<h3 class="sg-card-title">' . $esc(__('Recent Security Audit Logs (Last 100)', 'securityguard')) . '</h3>';
if ($canEdit) {
    echo '<form method="post" action="' . $esc($formUrl) . '" class="sg-inline-form">';
    echo '<input type="hidden" name="purge_logs" value="1">';
    echo '<button type="submit" class="btn btn-sm btn-outline-danger sg-btn-sm">' . $esc(__('Purge expired logs', 'securityguard')) . '</button>';
    Html::closeForm();
}
echo '</div>';

if ($logs === []) {
    echo '<p class="sg-empty">' . $esc(__('No audit events recorded yet.', 'securityguard')) . '</p>';
} else {
    echo '<div class="sg-table-wrap"><table class="sg-table">';
    echo '<thead><tr>';
    echo '<th>' . $esc(__('Date / Time', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('Severity', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('Event Type', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('Actor User ID', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('IP Address', 'securityguard')) . '</th>';
    echo '<th>' . $esc(__('Summary', 'securityguard')) . '</th>';
    echo '</tr></thead><tbody>';

    foreach ($logs as $logRow) {
        $sev      = strtolower((string) ($logRow['severity'] ?? 'info'));
        $badgeCls = 'sg-badge-info';
        if ($sev === 'critical') {
            $badgeCls = 'sg-badge-critical';
        } elseif ($sev === 'warning') {
            $badgeCls = 'sg-badge-warning';
        }

        echo '<tr>';
        echo '<td>' . $esc($logRow['date_creation'] ?? '') . '</td>';
        echo '<td><span class="sg-badge ' . $esc($badgeCls) . '">' . $esc(strtoupper($sev)) . '</span></td>';
        echo '<td><code>' . $esc($logRow['event_type'] ?? '') . '</code></td>';
        echo '<td>' . (int) ($logRow['actor_users_id'] ?? 0) . '</td>';
        echo '<td><code>' . $esc($logRow['ip_address'] ?? '') . '</code></td>';
        echo '<td>' . $esc($logRow['summary'] ?? '') . '</td>';
        echo '</tr>';
    }

    echo '</tbody></table></div>';
}
echo '</div>';

echo '</div>';

Html::footer();
