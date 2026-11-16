<?php

/**
 * ------------------------------------------------------------------------
 * Security Guard - Bootstrap de testes unitários standalone (sem Composer)
 *
 * Copyright (C) 2026 by G. Martins (GPLv3+)
 * ------------------------------------------------------------------------
 */

namespace Glpi\Toolbox {
    if (!class_exists(Sanitizer::class)) {
        class Sanitizer
        {
            /**
             * @param mixed $value
             * @return mixed
             */
            public static function sanitize($value)
            {
                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        $value[$k] = self::sanitize($v);
                    }
                    return $value;
                }
                if (!is_string($value)) {
                    return $value;
                }
                $encoded = str_replace(
                    ['&', '<', '>', "'", '"'],
                    ['&#38;', '&#60;', '&#62;', '&#39;', '&#34;'],
                    $value
                );
                return addslashes($encoded);
            }

            /**
             * @param mixed $value
             * @return mixed
             */
            public static function decodeHtmlSpecialChars($value)
            {
                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        $value[$k] = self::decodeHtmlSpecialChars($v);
                    }
                    return $value;
                }
                if (!is_string($value)) {
                    return $value;
                }
                return str_replace(
                    ['&#60;', '&#62;', '&#38;', '&#39;', '&#34;', '&lt;', '&gt;', '&amp;', '&#039;', '&quot;'],
                    ['<', '>', '&', "'", '"', '<', '>', '&', "'", '"'],
                    $value
                );
            }

            /**
             * @param mixed $value
             * @return mixed
             */
            public static function unsanitize($value)
            {
                if (is_array($value)) {
                    foreach ($value as $k => $v) {
                        $value[$k] = self::unsanitize($v);
                    }
                    return $value;
                }
                if (!is_string($value)) {
                    return $value;
                }
                return self::decodeHtmlSpecialChars(stripslashes($value));
            }
        }
    }
}

namespace Glpi\Exception\Http {
    if (!class_exists(AccessDeniedHttpException::class)) {
        class AccessDeniedHttpException extends \RuntimeException
        {
        }
    }
}

namespace {
    if (!defined('GLPI_ROOT')) {
        define('GLPI_ROOT', dirname(__DIR__));
    }

    $envVersion = getenv('SECURITYGUARD_TEST_GLPI_VERSION');
    if (!defined('GLPI_VERSION')) {
        define('GLPI_VERSION', ($envVersion !== false && $envVersion !== '') ? $envVersion : '11.0.0');
    }

    if (!defined('INFO')) {
        define('INFO', 0);
    }
    if (!defined('WARNING')) {
        define('WARNING', 2);
    }
    if (!defined('ERROR')) {
        define('ERROR', 3);
    }
    if (!defined('READ')) {
        define('READ', 1);
    }
    if (!defined('UPDATE')) {
        define('UPDATE', 2);
    }
    if (!defined('CREATE')) {
        define('CREATE', 4);
    }
    if (!defined('PURGE')) {
        define('PURGE', 128);
    }

    $GLOBALS['TEST_CLI_MODE'] = false;
    $GLOBALS['PLUGIN_HOOKS']  = [];
    $GLOBALS['CFG_GLPI']      = [
        'root_doc' => '',
        'url_base' => 'https://glpi.local',
    ];

    if (!function_exists('__')) {
        function __($str, $domain = 'glpi')
        {
            return (string) $str;
        }
    }

    if (!function_exists('isCommandLineInterface')) {
        function isCommandLineInterface()
        {
            return !empty($GLOBALS['TEST_CLI_MODE']);
        }
    }

    $typedRightname = getenv('SECURITYGUARD_TEST_TYPED_RIGHTNAME') === '1';
    if ($typedRightname) {
        class CommonGLPI
        {
            public static string $rightname = '';

            public static function getType()
            {
                return static::class;
            }
        }
    } else {
        class CommonGLPI
        {
            public static $rightname = '';

            public static function getType()
            {
                return static::class;
            }
        }
    }

    class CommonDBTM extends CommonGLPI
    {
        /** @var array<string, mixed> */
        public $fields = [];

        /** @var array<string, mixed>|false */
        public $input = [];

        /** @var array<int, string> */
        public $updates = [];

        /** @var array<string, mixed> */
        public $oldvalues = [];

        public function getID()
        {
            return (int) ($this->fields['id'] ?? 0);
        }
    }

    class User extends CommonDBTM
    {
    }

    class Profile_User extends CommonDBTM
    {
    }

    class DBConnection
    {
        public static function getDefaultCharset(): string
        {
            return 'utf8mb4';
        }

        public static function getDefaultCollation(): string
        {
            return 'utf8mb4_unicode_ci';
        }
    }

    /**
     * Simula GLPI 10.0.0–10.0.10 onde DBmysql::doQuery() não existia (apenas query()).
     */
    class LegacyQueryOnlyDB
    {
        /** @var array<string, array<int, array<string, mixed>>> */
        public $tables = [];

        /** @var array<int, string> */
        public $queries = [];

        public function tableExists(string $table): bool
        {
            return isset($this->tables[$table]);
        }

        public function query(string $sql): bool
        {
            $this->queries[] = $sql;
            if (preg_match('/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                $this->tables[$m[1]] = [];
                return true;
            }
            if (preg_match('/DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                unset($this->tables[$m[1]]);
                return true;
            }
            return true;
        }
    }

    class DBmysql
    {
        /** @var array<string, array<int, array<string, mixed>>> */
        private $tables = [];

        /** @var array<string, int> */
        private $autoIncrement = [];

        public function __construct()
        {
            $this->reset();
        }

        public function reset(): void
        {
            $this->tables = [
                'glpi_users'         => [],
                'glpi_profiles'      => [],
                'glpi_profilerights' => [],
            ];
            $this->autoIncrement = [
                'glpi_users'         => 0,
                'glpi_profiles'      => 0,
                'glpi_profilerights' => 0,
            ];
        }

        public function tableExists(string $table): bool
        {
            return isset($this->tables[$table]);
        }

        public function doQuery(string $sql): bool
        {
            if (preg_match('/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                $table = $m[1];
                if (!isset($this->tables[$table])) {
                    $this->tables[$table]        = [];
                    $this->autoIncrement[$table] = 0;
                }
                return true;
            }
            if (preg_match('/DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?`?([a-zA-Z0-9_]+)`?/i', $sql, $m)) {
                $table = $m[1];
                unset($this->tables[$table], $this->autoIncrement[$table]);
                return true;
            }
            return true;
        }

        public function escape(string $value): string
        {
            return addslashes($value);
        }

        public function request(array $criteria)
        {
            $from = (string) ($criteria['FROM'] ?? '');
            $rows = $this->tables[$from] ?? [];

            $where   = (array) ($criteria['WHERE'] ?? []);
            $matched = [];
            foreach ($rows as $row) {
                if ($this->matchesWhere($row, $where)) {
                    $matched[] = $row;
                }
            }

            if (!empty($criteria['ORDER'])) {
                $orders = is_array($criteria['ORDER']) ? $criteria['ORDER'] : [$criteria['ORDER']];
                $first  = trim((string) ($orders[0] ?? ''));
                if ($first !== '') {
                    $parts = preg_split('/\s+/', $first);
                    $col   = $parts[0] ?? 'id';
                    $dir   = strtoupper((string) ($parts[1] ?? 'ASC'));
                    usort($matched, static function (array $a, array $b) use ($col, $dir): int {
                        $va = $a[$col] ?? null;
                        $vb = $b[$col] ?? null;
                        if ($va == $vb) {
                            return 0;
                        }
                        $cmp = ($va < $vb) ? -1 : 1;
                        return $dir === 'DESC' ? -$cmp : $cmp;
                    });
                }
            }

            if (isset($criteria['LIMIT'])) {
                $limit   = max(0, (int) $criteria['LIMIT']);
                $matched = array_slice($matched, 0, $limit);
            }

            return new \ArrayIterator($matched);
        }

        public function insert(string $table, array $params): bool
        {
            if (!isset($this->tables[$table])) {
                $this->tables[$table] = [];
            }
            $params = $this->normalizeDbWriteValues($params);
            if (!isset($params['id'])) {
                $next                        = ($this->autoIncrement[$table] ?? 0) + 1;
                $this->autoIncrement[$table] = $next;
                $params['id']                = $next;
            } else {
                $params['id'] = (int) $params['id'];
                if ($params['id'] > ($this->autoIncrement[$table] ?? 0)) {
                    $this->autoIncrement[$table] = $params['id'];
                }
            }
            $this->tables[$table][] = $params;
            return true;
        }

        public function update(string $table, array $params, array $where): bool
        {
            if (!isset($this->tables[$table])) {
                return false;
            }
            $params = $this->normalizeDbWriteValues($params);
            foreach ($this->tables[$table] as $idx => $row) {
                if ($this->matchesWhere($row, $where)) {
                    foreach ($params as $k => $v) {
                        $this->tables[$table][$idx][$k] = $v;
                    }
                }
            }
            return true;
        }

        public function delete(string $table, array $where): bool
        {
            if (!isset($this->tables[$table])) {
                return true;
            }
            $kept = [];
            foreach ($this->tables[$table] as $row) {
                if (!$this->matchesWhere($row, $where)) {
                    $kept[] = $row;
                }
            }
            $this->tables[$table] = $kept;
            return true;
        }

        private function normalizeDbWriteValues(array $params): array
        {
            if (version_compare((string) GLPI_VERSION, '11.0.0-dev', '<')) {
                foreach ($params as $k => $v) {
                    if (is_string($v)) {
                        $params[$k] = stripslashes($v);
                    }
                }
            }
            return $params;
        }

        private function matchesWhere(array $row, array $where): bool
        {
            foreach ($where as $k => $expected) {
                if (!array_key_exists($k, $row)) {
                    return false;
                }
                $actual = $row[$k];
                if (is_array($expected)) {
                    if (!in_array($actual, $expected)) {
                        return false;
                    }
                } elseif ((string) $actual !== (string) $expected) {
                    return false;
                }
            }
            return true;
        }
    }

    class Config
    {
        /** @var array<string, array<string, mixed>> */
        public static $store = [];

        public static function getConfigurationValues(string $context): array
        {
            return self::$store[$context] ?? [];
        }

        public static function setConfigurationValues(string $context, array $values): void
        {
            if (!isset(self::$store[$context])) {
                self::$store[$context] = [];
            }
            foreach ($values as $k => $v) {
                self::$store[$context][$k] = $v;
            }
        }

        public static function deleteConfigurationValues(string $context, array $keys): void
        {
            foreach ($keys as $k) {
                unset(self::$store[$context][$k]);
            }
        }
    }

    class Session
    {
        /** @var int */
        public static $loginUserId = 2;

        /** @var array<int, array{msg: string, check_once: bool, type: int}> */
        public static $messages = [];

        /** @var array<string, int> */
        public static $rights = ['config' => 3];

        public static function reset(): void
        {
            self::$loginUserId = 2;
            self::$messages    = [];
            self::$rights      = ['config' => READ | UPDATE];
            $_SESSION          = [];
        }

        public static function getLoginUserID($force_human = true)
        {
            return self::$loginUserId > 0 ? self::$loginUserId : false;
        }

        public static function addMessageAfterRedirect($msg, $check_once = false, $message_type = INFO, $reset = false): void
        {
            if ($reset) {
                self::$messages = [];
            }
            self::$messages[] = [
                'msg'        => (string) $msg,
                'check_once' => (bool) $check_once,
                'type'       => (int) $message_type,
            ];
        }

        public static function haveRight($module, $right): bool
        {
            $mask = (int) (self::$rights[$module] ?? 0);
            return ($mask & (int) $right) === (int) $right;
        }

        public static function checkRight($module, $right): void
        {
            if (!self::haveRight($module, $right)) {
                throw new \RuntimeException('Right denied: ' . $module);
            }
        }
    }

    class Plugin
    {
        /** @var array<int, string> */
        public static $registered = [];

        /** @var bool */
        public static $webDirCalled = false;

        public static function registerClass($class, $params = []): void
        {
            self::$registered[] = (string) $class;
        }

        public static function getWebDir($plugin, $full = false): string
        {
            self::$webDirCalled = true;
            return '/plugins/' . $plugin;
        }
    }

    if (version_compare((string) GLPI_VERSION, '12.0.0-dev', '<')) {
        class Html
        {
            /** @var bool */
            public static $rightErrorDisplayed = false;

            /** @var string|null */
            public static $lastRedirect = null;

            public static function closeForm($display = true): string
            {
                $out = '<input type="hidden" name="_glpi_csrf_token" value="test"></form>';
                if ($display) {
                    echo $out;
                }
                return $out;
            }

            public static function header($title = '', $url = '', $sector = '', $item = ''): void
            {
            }

            public static function footer(): void
            {
            }

            public static function back(): void
            {
            }

            public static function redirect($location): void
            {
                self::$lastRedirect = (string) $location;
            }

            public static function displayRightError(): void
            {
                self::$rightErrorDisplayed = true;
            }
        }
    } else {
        class Html
        {
            /** @var string|null */
            public static $lastRedirect = null;

            public static function closeForm($display = true): string
            {
                $out = '<input type="hidden" name="_glpi_csrf_token" value="test"></form>';
                if ($display) {
                    echo $out;
                }
                return $out;
            }

            public static function header($title = '', $url = '', $sector = '', $item = ''): void
            {
            }

            public static function footer(): void
            {
            }

            public static function back(): void
            {
            }

            public static function redirect($location): void
            {
                self::$lastRedirect = (string) $location;
            }
        }
    }

    class Toolbox
    {
        /**
         * @param mixed $value
         * @return mixed
         */
        public static function addslashes_deep($value)
        {
            if (is_array($value)) {
                foreach ($value as $k => $v) {
                    $value[$k] = self::addslashes_deep($v);
                }
                return $value;
            }
            return is_string($value) ? addslashes($value) : $value;
        }
    }

    $GLOBALS['DB'] = new DBmysql();
    Session::reset();

    require_once GLPI_ROOT . '/securityguard/setup.php';
    require_once GLPI_ROOT . '/securityguard/hook.php';
    plugin_init_securityguard();
}
