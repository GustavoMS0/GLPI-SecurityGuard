<?php

/**
 * ------------------------------------------------------------------------
 * Security Guard - Rotinas de instalação e desinstalação
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

require_once __DIR__ . '/setup.php';

/**
 * Instala tabelas e configurações padrão do plugin.
 */
function plugin_securityguard_install(): bool
{
    PluginSecurityguardGuard::installSchema();
    PluginSecurityguardConfig::installDefaults();
    return true;
}

/**
 * Remove tabelas e configurações do plugin.
 */
function plugin_securityguard_uninstall(): bool
{
    PluginSecurityguardGuard::uninstallSchema();
    PluginSecurityguardConfig::uninstallConfig();
    return true;
}
