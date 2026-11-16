<?php

/**
 * ------------------------------------------------------------------------
 * Security Guard - Inicialização e metadados do plugin
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

define('PLUGIN_SECURITYGUARD_VERSION', '1.0.0');
define('PLUGIN_SECURITYGUARD_MIN_GLPI', '10.0.0');
define('PLUGIN_SECURITYGUARD_MAX_GLPI', '12.0.99');
define('PLUGIN_SECURITYGUARD_MIN_PHP', '7.4');

require_once __DIR__ . '/inc/compat.class.php';
require_once __DIR__ . '/inc/config.class.php';
require_once __DIR__ . '/inc/guard.class.php';

/**
 * Registra os hooks e recursos do plugin no GLPI.
 */
function plugin_init_securityguard(): void
{
    global $PLUGIN_HOOKS;

    $PLUGIN_HOOKS['csrf_compliant']['securityguard'] = true;
    $PLUGIN_HOOKS['config_page']['securityguard']    = 'front/config.form.php';
    $PLUGIN_HOOKS['add_css']['securityguard']        = [
        PluginSecurityguardCompat::assetPath('css/securityguard.css'),
    ];

    $PLUGIN_HOOKS['post_init']['securityguard']    = [PluginSecurityguardGuard::class, 'onPostInit'];
    $PLUGIN_HOOKS['init_session']['securityguard'] = [PluginSecurityguardGuard::class, 'onInitSession'];

    $PLUGIN_HOOKS['item_add']['securityguard'] = [
        'Profile_User' => [PluginSecurityguardGuard::class, 'onItemAdd'],
        'User'         => [PluginSecurityguardGuard::class, 'onItemAdd'],
    ];
    $PLUGIN_HOOKS['item_update']['securityguard'] = [
        'User' => [PluginSecurityguardGuard::class, 'onItemUpdate'],
    ];
    $PLUGIN_HOOKS['item_delete']['securityguard'] = [
        'Profile_User' => [PluginSecurityguardGuard::class, 'onItemDelete'],
        'User'         => [PluginSecurityguardGuard::class, 'onItemDelete'],
    ];
    $PLUGIN_HOOKS['item_purge']['securityguard'] = [
        'Profile_User' => [PluginSecurityguardGuard::class, 'onItemPurge'],
        'User'         => [PluginSecurityguardGuard::class, 'onItemPurge'],
    ];
}

/**
 * Metadados e requisitos de compatibilidade do plugin.
 *
 * @return array<string, mixed>
 */
function plugin_version_securityguard(): array
{
    return [
        'name'         => __('Security Guard', 'securityguard'),
        'version'      => PLUGIN_SECURITYGUARD_VERSION,
        'author'       => 'G. Martins',
        'license'      => 'GPLv3+',
        'homepage'     => 'https://github.com/GustavoMS0/GLPI-SecurityGuard',
        'requirements' => [
            'glpi' => [
                'min' => PLUGIN_SECURITYGUARD_MIN_GLPI,
                'max' => PLUGIN_SECURITYGUARD_MAX_GLPI,
            ],
            'php' => [
                'min' => PLUGIN_SECURITYGUARD_MIN_PHP,
            ],
        ],
    ];
}

/**
 * Verifica os pré-requisitos de versão do PHP e do GLPI.
 */
function plugin_securityguard_check_prerequisites(): bool
{
    if (version_compare(PHP_VERSION, PLUGIN_SECURITYGUARD_MIN_PHP, '<')) {
        echo sprintf(
            __('This plugin requires PHP >= %s.', 'securityguard'),
            PLUGIN_SECURITYGUARD_MIN_PHP
        );
        return false;
    }

    if (defined('GLPI_VERSION')) {
        if (
            version_compare(GLPI_VERSION, PLUGIN_SECURITYGUARD_MIN_GLPI, '<')
            || version_compare(GLPI_VERSION, PLUGIN_SECURITYGUARD_MAX_GLPI, '>')
        ) {
            echo sprintf(
                __('This plugin requires GLPI >= %1$s and <= %2$s.', 'securityguard'),
                PLUGIN_SECURITYGUARD_MIN_GLPI,
                PLUGIN_SECURITYGUARD_MAX_GLPI
            );
            return false;
        }
    }

    return true;
}

/**
 * Verifica a configuração do plugin.
 *
 * @param bool $verbose
 */
function plugin_securityguard_check_config($verbose = false): bool
{
    return true;
}
