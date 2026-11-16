<?php

/**
 * ------------------------------------------------------------------------
 * Security Guard - Suíte de testes unitários standalone
 *
 * Copyright (C) 2026 by G. Martins (GPLv3+)
 * ------------------------------------------------------------------------
 */

require_once __DIR__ . '/bootstrap.php';

function assertSame($expected, $actual, string $label): void
{
    if ($expected !== $actual) {
        throw new RuntimeException(
            sprintf(
                "Falha em [%s]: esperado %s, obtido %s",
                $label,
                var_export($expected, true),
                var_export($actual, true)
            )
        );
    }
}

function assertTrue($condition, string $label): void
{
    if ($condition !== true) {
        throw new RuntimeException(sprintf("Falha em [%s]: esperado true", $label));
    }
}

function resetEnvironment(): void
{
    global $DB;
    $DB->reset();
    Config::$store = [];
    Session::reset();
    Plugin::$webDirCalled = false;
    if (property_exists('Html', 'rightErrorDisplayed')) {
        Html::$rightErrorDisplayed = false;
    }
    Html::$lastRedirect       = null;
    $GLOBALS['TEST_CLI_MODE'] = false;
    $_GET                     = [];
    $_POST                    = [];
    $_SERVER                  = [];
    PluginSecurityguardGuard::resetRuntimeState();
    plugin_securityguard_install();
}

function test_plugin_manifest_and_hooks(): void
{
    global $PLUGIN_HOOKS;
    resetEnvironment();

    plugin_init_securityguard();
    $info = plugin_version_securityguard();

    assertSame('1.0.0', $info['version'], 'versao do plugin');
    assertSame('G. Martins', $info['author'], 'autor do plugin');
    assertSame('GPLv3+', $info['license'], 'licenca do plugin');
    assertSame('10.0.0', $info['requirements']['glpi']['min'], 'GLPI min');
    assertSame('12.0.99', $info['requirements']['glpi']['max'], 'GLPI max');
    assertSame('7.4', $info['requirements']['php']['min'], 'PHP min');
    assertTrue(plugin_securityguard_check_prerequisites(), 'check_prerequisites');
    assertTrue(plugin_securityguard_check_config(), 'check_config');

    assertSame(true, $PLUGIN_HOOKS['csrf_compliant']['securityguard'] ?? null, 'csrf_compliant');
    assertSame('front/config.form.php', $PLUGIN_HOOKS['config_page']['securityguard'] ?? null, 'config_page');
    assertSame([PluginSecurityguardGuard::class, 'onPostInit'], $PLUGIN_HOOKS['post_init']['securityguard'] ?? null, 'post_init hook');
    assertSame([PluginSecurityguardGuard::class, 'onInitSession'], $PLUGIN_HOOKS['init_session']['securityguard'] ?? null, 'init_session hook');
}

function test_legacy_query_only_db_on_glpi_10_0_5(): void
{
    global $DB;
    resetEnvironment();

    $origDb = $DB;
    try {
        $legacyDb = new LegacyQueryOnlyDB();
        assertSame(false, method_exists($legacyDb, 'doQuery'), 'LegacyQueryOnlyDB nao possui doQuery');

        $DB = $legacyDb;
        PluginSecurityguardGuard::installSchema();

        assertTrue($legacyDb->tableExists(PluginSecurityguardGuard::TABLE_LOCKOUTS), 'cria tabela lockouts via query()');
        assertTrue($legacyDb->tableExists(PluginSecurityguardGuard::TABLE_LOGS), 'cria tabela logs via query()');
        assertSame(2, count($legacyDb->queries), '2 comandos CREATE TABLE executados');

        PluginSecurityguardGuard::uninstallSchema();
        assertSame(false, $legacyDb->tableExists(PluginSecurityguardGuard::TABLE_LOCKOUTS), 'remove tabela lockouts via query()');
        assertSame(false, $legacyDb->tableExists(PluginSecurityguardGuard::TABLE_LOGS), 'remove tabela logs via query()');
        assertSame(4, count($legacyDb->queries), '2 comandos DROP TABLE executados');
    } finally {
        $DB = $origDb;
    }
}

function test_brute_force_counter_and_pre_login_block(): void
{
    resetEnvironment();

    PluginSecurityguardConfig::saveConfig([
        'enabled'         => 1,
        'max_attempts'    => 3,
        'window_minutes'  => 15,
        'lockout_minutes' => 15,
        'audit_logins'    => 1,
    ]);

    $blockedCalls = [];
    PluginSecurityguardGuard::setBlockHandlerForTest(static function (array $ctx) use (&$blockedCalls): void {
        $blockedCalls[] = $ctx;
    });

    Session::$loginUserId = 0;

    // Tentativa 1 (GLPI 10 namfield dinâmico)
    PluginSecurityguardGuard::setNowForTest('2026-11-16 10:00:00');
    $_SESSION['namfield'] = 'field_a1b2c3';
    $_SERVER              = [
        'REQUEST_METHOD' => 'POST',
        'REQUEST_URI'    => '/front/login.php',
        'REMOTE_ADDR'    => '198.51.100.25',
    ];
    $_POST = ['field_a1b2c3' => 'alice'];

    assertSame(false, PluginSecurityguardGuard::onPostInit(), 'tentativa 1 nao bloqueada no pre-login');
    PluginSecurityguardGuard::evaluateLoginOutcome();

    // Tentativa 2 (GLPI 11/12 login_name)
    PluginSecurityguardGuard::setNowForTest('2026-11-16 10:02:00');
    $_POST = ['login_name' => 'alice'];
    assertSame(false, PluginSecurityguardGuard::onPostInit(), 'tentativa 2 nao bloqueada no pre-login');
    PluginSecurityguardGuard::evaluateLoginOutcome();

    // Tentativa 3 -> atinge max_attempts (3) e aciona bloqueio por 15 minutos
    PluginSecurityguardGuard::setNowForTest('2026-11-16 10:03:00');
    assertSame(false, PluginSecurityguardGuard::onPostInit(), 'tentativa 3 nao bloqueada antes da falha');
    PluginSecurityguardGuard::evaluateLoginOutcome();

    $active = PluginSecurityguardGuard::getActiveLockouts();
    assertSame(1, count($active), '1 bloqueio ativo apos 3 falhas');
    assertSame('alice', $active[0]['username'], 'usuario bloqueado e alice');
    assertSame('198.51.100.25', $active[0]['ip_address'], 'IP bloqueado e 198.51.100.25');
    assertSame('2026-11-16 10:18:00', $active[0]['locked_until'], 'locked_until = 10:03 + 15 min');

    // Tentativa 4 (Web): deve ser bloqueada no onPostInit ANTES de Auth::login()
    PluginSecurityguardGuard::setNowForTest('2026-11-16 10:05:00');
    assertTrue(PluginSecurityguardGuard::onPostInit(), 'tentativa 4 bloqueada imediatamente em onPostInit');
    assertSame(1, count($blockedCalls), 'blockHandler chamado na tentativa 4');
    assertSame(false, $blockedCalls[0]['is_api'], 'bloqueio web identificado');
    assertSame(302, $blockedCalls[0]['status'], 'status web redirect');

    // Tentativa 5 (REST API initSession): deve ser bloqueada com HTTP 429
    $_SERVER = [
        'REQUEST_METHOD' => 'GET',
        'REQUEST_URI'    => '/apirest.php/initSession',
        'REMOTE_ADDR'    => '198.51.100.25',
        'PHP_AUTH_USER'  => 'alice',
    ];
    $_POST = [];
    assertTrue(PluginSecurityguardGuard::onPostInit(), 'tentativa API bloqueada imediatamente em onPostInit');
    assertSame(2, count($blockedCalls), 'blockHandler chamado para REST API');
    assertSame(true, $blockedCalls[1]['is_api'], 'bloqueio API identificado');
    assertSame(429, $blockedCalls[1]['status'], 'status HTTP 429 na API');

    // Após expirar o bloqueio (10:20:00 > 10:18:00), o pre-login permite nova tentativa
    PluginSecurityguardGuard::setNowForTest('2026-11-16 10:20:00');
    assertSame(false, PluginSecurityguardGuard::onPostInit(), 'bloqueio expirado libera nova tentativa');
}

function test_init_session_resets_lockout_and_logs_success(): void
{
    resetEnvironment();

    PluginSecurityguardConfig::saveConfig([
        'enabled'      => 1,
        'max_attempts' => 4,
        'audit_logins' => 1,
    ]);

    Session::$loginUserId = 0;
    PluginSecurityguardGuard::setNowForTest('2026-11-16 11:00:00');
    $_SERVER = [
        'REQUEST_METHOD' => 'POST',
        'REQUEST_URI'    => '/front/login.php',
        'REMOTE_ADDR'    => '198.51.100.88',
    ];
    $_POST = ['login_name' => 'bob'];

    // 2 falhas seguidas
    PluginSecurityguardGuard::onPostInit();
    PluginSecurityguardGuard::evaluateLoginOutcome();
    PluginSecurityguardGuard::onPostInit();
    PluginSecurityguardGuard::evaluateLoginOutcome();

    // 3a tentativa tem sucesso: init_session é disparado pelo GLPI
    PluginSecurityguardGuard::onPostInit();
    Session::$loginUserId = 42;
    $_SESSION['glpiname'] = 'bob';
    PluginSecurityguardGuard::onInitSession();
    PluginSecurityguardGuard::evaluateLoginOutcome();

    // O contador deve ter sido zerado; mais 2 falhas NÃO devem bloquear (max_attempts = 4)
    Session::$loginUserId = 0;
    PluginSecurityguardGuard::onPostInit();
    PluginSecurityguardGuard::evaluateLoginOutcome();
    PluginSecurityguardGuard::onPostInit();
    PluginSecurityguardGuard::evaluateLoginOutcome();

    assertSame(0, count(PluginSecurityguardGuard::getActiveLockouts()), 'nenhum bloqueio ativo pois init_session limpou falhas anteriores');

    $logs       = PluginSecurityguardGuard::getRecentLogs(20);
    $hasSuccess = false;
    foreach ($logs as $log) {
        if ($log['event_type'] === 'login_success' && (int) $log['actor_users_id'] === 42) {
            $hasSuccess = true;
            break;
        }
    }
    assertTrue($hasSuccess, 'evento login_success registrado para usuario #42');
}

function test_xff_spoof_protection_and_ip_allowlist(): void
{
    resetEnvironment();

    // 1. trust_proxy = 0: X-Forwarded-For forjado deve ser ignorado
    PluginSecurityguardConfig::saveConfig([
        'enabled'         => 1,
        'trust_proxy'     => 0,
        'trusted_proxies' => '10.0.0.1',
        'ip_allowlist'    => '',
    ]);

    $_SERVER = [
        'REMOTE_ADDR'          => '203.0.113.99',
        'HTTP_X_FORWARDED_FOR' => '1.2.3.4',
    ];
    assertSame('203.0.113.99', PluginSecurityguardGuard::resolveClientIp(), 'ignora XFF quando trust_proxy=0');

    // 2. trust_proxy = 1, mas REMOTE_ADDR NÃO pertence a trusted_proxies: continua ignorando XFF
    PluginSecurityguardConfig::saveConfig([
        'trust_proxy'     => 1,
        'trusted_proxies' => '10.0.0.1, 172.16.0.0/12',
    ]);
    assertSame('203.0.113.99', PluginSecurityguardGuard::resolveClientIp(), 'ignora XFF quando REMOTE_ADDR nao e proxy confiavel');

    // 3. trust_proxy = 1 e REMOTE_ADDR pertence a trusted_proxies: extrai IP real do cliente
    $_SERVER = [
        'REMOTE_ADDR'          => '172.20.0.5',
        'HTTP_X_FORWARDED_FOR' => '198.51.100.77, 10.0.0.1',
    ];
    assertSame('198.51.100.77', PluginSecurityguardGuard::resolveClientIp(), 'extrai IP real quando REMOTE_ADDR pertence a CIDR de proxy confiavel');

    // 4. ip_allowlist: IP na allowlist nunca sofre bloqueio mesmo após N falhas
    PluginSecurityguardConfig::saveConfig([
        'max_attempts' => 3,
        'ip_allowlist' => '198.51.100.0/24, 127.0.0.1',
    ]);

    Session::$loginUserId = 0;
    $_SERVER              = [
        'REQUEST_METHOD' => 'POST',
        'REQUEST_URI'    => '/front/login.php',
        'REMOTE_ADDR'    => '198.51.100.77',
    ];
    $_POST = ['login_name' => 'admin'];

    for ($i = 0; $i < 6; $i++) {
        assertSame(false, PluginSecurityguardGuard::onPostInit(), 'IP na allowlist nunca e bloqueado');
        PluginSecurityguardGuard::evaluateLoginOutcome();
    }
    assertSame(0, count(PluginSecurityguardGuard::getActiveLockouts()), 'nenhum lockout criado para IP na allowlist');
}

function test_sensitive_audit_events_never_leak_passwords_or_tokens(): void
{
    global $DB;
    resetEnvironment();

    // Cadastra perfil #4 com config:UPDATE e perfil #2 sem config:UPDATE
    $DB->insert('glpi_profilerights', [
        'profiles_id' => 4,
        'name'        => 'config',
        'rights'      => READ | UPDATE,
    ]);
    $DB->insert('glpi_profilerights', [
        'profiles_id' => 2,
        'name'        => 'config',
        'rights'      => READ,
    ]);

    Session::$loginUserId = 2;
    $_SERVER['REMOTE_ADDR'] = '192.0.2.15';

    // 1. Atribuição de perfil administrativo (#4) e remoção
    $puHigh         = new Profile_User();
    $puHigh->fields = ['id' => 10, 'users_id' => 55, 'profiles_id' => 4, 'entities_id' => 0];
    PluginSecurityguardGuard::onItemAdd($puHigh);
    PluginSecurityguardGuard::onItemDelete($puHigh);

    // 2. Criação de usuário
    $newUser         = new User();
    $newUser->fields = ['id' => 55, 'name' => 'carlos.sec'];
    PluginSecurityguardGuard::onItemAdd($newUser);

    // 3. Atualização de senha, tokens e status (com valores secretos que NUNCA podem ir para o log)
    $secretHash  = '$2y$10$UltraSecretBcryptPasswordHashValue999999';
    $secretToken = 'glpi_personal_token_super_secret_abcdef123456';
    $secretApi   = 'glpi_api_token_super_secret_xyz987654';

    $updUser            = new User();
    $updUser->fields    = [
        'id'             => 55,
        'name'           => 'carlos.sec',
        'password'       => $secretHash,
        'personal_token' => $secretToken,
        'api_token'      => $secretApi,
        'is_active'      => 0,
        'is_deleted'     => 1,
    ];
    $updUser->updates   = ['password', 'personal_token', 'api_token', 'is_active', 'is_deleted'];
    $updUser->oldvalues = ['password' => 'old', 'is_active' => 1, 'is_deleted' => 0];
    PluginSecurityguardGuard::onItemUpdate($updUser);

    // 4. Expurgo permanente de usuário
    PluginSecurityguardGuard::onItemPurge($updUser);

    $logs       = PluginSecurityguardGuard::getRecentLogs(50);
    $eventTypes = [];
    $severities = [];

    foreach ($logs as $row) {
        $eventTypes[$row['event_type']] = true;
        if ($row['event_type'] === 'profile_assigned') {
            $severities['profile_assigned'] = $row['severity'];
        }
        $serialized = json_encode($row);
        assertSame(false, strpos((string) $serialized, $secretHash), 'hash de senha jamais aparece no log');
        assertSame(false, strpos((string) $serialized, $secretToken), 'personal_token jamais aparece no log');
        assertSame(false, strpos((string) $serialized, $secretApi), 'api_token jamais aparece no log');
    }

    assertTrue(isset($eventTypes['profile_assigned']), 'registrou profile_assigned');
    assertSame('critical', $severities['profile_assigned'] ?? '', 'perfil com config:UPDATE gera severidade critical');
    assertTrue(isset($eventTypes['profile_removed']), 'registrou profile_removed');
    assertTrue(isset($eventTypes['user_created']), 'registrou user_created');
    assertTrue(isset($eventTypes['password_changed']), 'registrou password_changed');
    assertTrue(isset($eventTypes['token_changed']), 'registrou token_changed');
    assertTrue(isset($eventTypes['user_status_changed']), 'registrou user_status_changed');
    assertTrue(isset($eventTypes['user_purged']), 'registrou user_purged');
}

function test_manual_unlock_log_retention_and_config_form(): void
{
    resetEnvironment();

    PluginSecurityguardConfig::saveConfig([
        'enabled'        => 1,
        'max_attempts'   => 3,
        'retention_days' => 30,
    ]);

    PluginSecurityguardGuard::setNowForTest('2026-11-16 12:00:00');
    PluginSecurityguardGuard::recordFailedAttempt('locked.user', '198.51.100.200');
    PluginSecurityguardGuard::recordFailedAttempt('locked.user', '198.51.100.200');
    PluginSecurityguardGuard::recordFailedAttempt('locked.user', '198.51.100.200');

    $lockouts = PluginSecurityguardGuard::getActiveLockouts();
    assertSame(1, count($lockouts), '1 bloqueio ativo antes do unlock manual');
    $lockId = (int) $lockouts[0]['id'];

    // Desbloqueio via POST em front/config.form.php
    $_SERVER = [
        'REQUEST_METHOD'      => 'POST',
        'HTTP_SEC_FETCH_SITE' => 'same-origin',
    ];
    $_POST = ['unlock_id' => (string) $lockId];
    ob_start();
    include GLPI_ROOT . '/securityguard/front/config.form.php';
    ob_end_clean();

    assertSame(0, count(PluginSecurityguardGuard::getActiveLockouts()), 'bloqueio removido via unlock_id POST');

    // Grava um log antigo (60 dias atrás) e executa purge_logs via POST (retention_days = 30)
    PluginSecurityguardGuard::setNowForTest('2026-09-01 08:00:00');
    PluginSecurityguardGuard::recordLog('old_event', 'info', 2, 'User', 2, '127.0.0.1', 'Old audit entry');

    PluginSecurityguardGuard::setNowForTest('2026-11-16 12:05:00');
    $_POST = ['purge_logs' => '1'];
    ob_start();
    include GLPI_ROOT . '/securityguard/front/config.form.php';
    ob_end_clean();

    foreach (PluginSecurityguardGuard::getRecentLogs(100) as $log) {
        assertTrue($log['event_type'] !== 'old_event', 'log antigo acima de retention_days foi expurgado');
    }

    // Renderização GET do painel administrativo com escape contra XSS
    PluginSecurityguardGuard::recordLog('xss_test', 'warning', 2, 'User', 2, '127.0.0.1', '<script>alert(1)</script>');
    $_SERVER = ['REQUEST_METHOD' => 'GET'];
    $_POST   = [];
    ob_start();
    include GLPI_ROOT . '/securityguard/front/config.form.php';
    $html = (string) ob_get_clean();

    assertSame(false, strpos($html, '<script>alert(1)</script>'), 'nenhuma tag script crua no HTML');
    assertTrue(strpos($html, '&lt;script&gt;alert(1)&lt;/script&gt;') !== false, 'resumo escapado com htmlspecialchars');
}

function runIsolatedPhpAssertion(array $env, string $code): void
{
    $descriptorSpec = [
        0 => ['pipe', 'r'],
        1 => ['pipe', 'w'],
        2 => ['pipe', 'w'],
    ];
    $cmdEnv = array_merge($_ENV, $env);
    foreach ($_SERVER as $k => $v) {
        if (is_string($v) && !isset($cmdEnv[$k])) {
            $cmdEnv[$k] = $v;
        }
    }

    $oneLineCode = trim((string) preg_replace('/\s+/', ' ', $code));
    $process     = proc_open([PHP_BINARY, '-r', $oneLineCode], $descriptorSpec, $pipes, dirname(__DIR__), $cmdEnv);
    if (!is_resource($process)) {
        throw new RuntimeException('Falha ao iniciar subprocesso PHP');
    }

    fclose($pipes[0]);
    $stdout   = stream_get_contents($pipes[1]);
    $stderr   = stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    $exitCode = proc_close($process);

    if ($exitCode !== 0) {
        throw new RuntimeException(
            sprintf("Subprocesso falhou (codigo %d). STDOUT: %s | STDERR: %s", $exitCode, $stdout, $stderr)
        );
    }
}

function test_glpi_10_11_12_subprocesses(): void
{
    // 1) GLPI 10.0.18 (untyped $rightname, public/ asset prefix, fromCore preserva barras invertidas)
    runIsolatedPhpAssertion(
        [
            'SECURITYGUARD_TEST_TYPED_RIGHTNAME' => '0',
            'SECURITYGUARD_TEST_GLPI_VERSION'    => '10.0.18',
        ],
        '
        require "tests/bootstrap.php";
        if (PluginSecurityguardCompat::typedRightname() !== false) { exit(1); }
        $ref = new ReflectionProperty("PluginSecurityguardConfig", "rightname");
        if ($ref->hasType()) { exit(2); }
        if (PluginSecurityguardCompat::glpiMajor() !== 10) { exit(3); }
        if (PluginSecurityguardCompat::assetPath("css/securityguard.css") !== "public/css/securityguard.css") { exit(4); }
        $bs = chr(92);
        if (PluginSecurityguardCompat::fromCore("DOMAIN" . $bs . "user &amp; &#039;admin&#039;") !== "DOMAIN" . $bs . "user & \x27admin\x27") { exit(5); }
        PluginSecurityguardCompat::denyAccess();
        if (Html::$rightErrorDisplayed !== true) { exit(6); }
        exit(0);
        '
    );

    // 2) GLPI 11.0.0 (webPath retorna /plugins/securityguard sem chamar Plugin::getWebDir)
    runIsolatedPhpAssertion(
        [
            'SECURITYGUARD_TEST_TYPED_RIGHTNAME' => '1',
            'SECURITYGUARD_TEST_GLPI_VERSION'    => '11.0.0',
        ],
        '
        require "tests/bootstrap.php";
        if (PluginSecurityguardCompat::typedRightname() !== true) { exit(1); }
        if (PluginSecurityguardCompat::glpiMajor() !== 11) { exit(2); }
        if (PluginSecurityguardCompat::assetPath("css/securityguard.css") !== "css/securityguard.css") { exit(3); }
        if (PluginSecurityguardCompat::webPath(false) !== "/plugins/securityguard") { exit(4); }
        if (PluginSecurityguardCompat::webPath(true) !== "https://glpi.local/plugins/securityguard") { exit(5); }
        if (Plugin::$webDirCalled !== false) { exit(6); }
        exit(0);
        '
    );

    // 3) GLPI 12.0.0 (typed $rightname + AccessDeniedHttpException em denyAccess)
    runIsolatedPhpAssertion(
        [
            'SECURITYGUARD_TEST_TYPED_RIGHTNAME' => '1',
            'SECURITYGUARD_TEST_GLPI_VERSION'    => '12.0.0',
        ],
        '
        require "tests/bootstrap.php";
        $ref = new ReflectionProperty("PluginSecurityguardConfig", "rightname");
        if (!$ref->hasType()) { exit(1); }
        if (PluginSecurityguardCompat::glpiMajor() !== 12) { exit(2); }
        $threw = false;
        try {
            PluginSecurityguardCompat::denyAccess();
        } catch (\Glpi\Exception\Http\AccessDeniedHttpException $e) {
            $threw = true;
        }
        if (!$threw) { exit(3); }
        exit(0);
        '
    );

    // 4) Uninstall limpa tabelas e configurações
    global $DB;
    resetEnvironment();
    assertTrue($DB->tableExists(PluginSecurityguardGuard::TABLE_LOCKOUTS), 'lockouts existe apos install');
    assertTrue($DB->tableExists(PluginSecurityguardGuard::TABLE_LOGS), 'logs existe apos install');
    plugin_securityguard_uninstall();
    assertSame(false, $DB->tableExists(PluginSecurityguardGuard::TABLE_LOCKOUTS), 'lockouts removida no uninstall');
    assertSame(false, $DB->tableExists(PluginSecurityguardGuard::TABLE_LOGS), 'logs removida no uninstall');
    assertSame([], Config::getConfigurationValues(PluginSecurityguardConfig::CONTEXT), 'config removida no uninstall');
}

$tests = [
    'test_plugin_manifest_and_hooks',
    'test_legacy_query_only_db_on_glpi_10_0_5',
    'test_brute_force_counter_and_pre_login_block',
    'test_init_session_resets_lockout_and_logs_success',
    'test_xff_spoof_protection_and_ip_allowlist',
    'test_sensitive_audit_events_never_leak_passwords_or_tokens',
    'test_manual_unlock_log_retention_and_config_form',
    'test_glpi_10_11_12_subprocesses',
];

$passed = 0;
foreach ($tests as $testFn) {
    $testFn();
    $passed++;
    echo "[OK] {$testFn}\n";
}

echo sprintf("Todos os %d testes passaram com sucesso.\n", $passed);
