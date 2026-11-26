<?php

declare(strict_types=1);

namespace Hopr\Auth;

use RuntimeException;

final class Config
{
    /** @var array<string, mixed> */
    private array $data;

    /**
     * @param array<string, mixed> $data
     */
    private function __construct(array $data)
    {
        $this->data = $data;
    }

    public static function load(string $baseDir): self
    {
        $env = self::parseEnvFile($baseDir . '/.env');

        $phpConfigPath = $baseDir . '/config/config.php';
        $phpConfig = is_file($phpConfigPath) ? (array) require $phpConfigPath : [];

        $appEnv = $env['APP_ENV'] ?? ($phpConfig['app']['env'] ?? 'production');
        $pepper = $env['APP_PEPPER'] ?? ($phpConfig['app']['pepper'] ?? '');

        if ($pepper === '' || str_starts_with((string) $pepper, 'CHANGE_ME')) {
            throw new RuntimeException('APP_PEPPER is not configured.');
        }

        $trustedRaw = $env['TRUSTED_PROXIES'] ?? '';
        $trustedProxies = $trustedRaw !== ''
            ? array_values(array_filter(array_map('trim', explode(',', $trustedRaw))))
            : ($phpConfig['security']['trusted_proxies'] ?? []);

        return new self([
            'app' => [
                'env' => $appEnv,
                'debug' => filter_var($env['APP_DEBUG'] ?? ($phpConfig['app']['debug'] ?? false), FILTER_VALIDATE_BOOL),
                'name' => $env['APP_NAME'] ?? ($phpConfig['app']['name'] ?? 'Hopr'),
                'pepper' => (string) $pepper,
            ],
            'db' => [
                'host' => $env['DB_HOST'] ?? ($phpConfig['db']['host'] ?? '127.0.0.1'),
                'port' => (int) ($env['DB_PORT'] ?? ($phpConfig['db']['port'] ?? 3306)),
                'name' => $env['DB_NAME'] ?? ($phpConfig['db']['name'] ?? ''),
                'user' => $env['DB_USER'] ?? ($phpConfig['db']['user'] ?? ''),
                'pass' => $env['DB_PASS'] ?? ($phpConfig['db']['pass'] ?? ''),
            ],
            'smtp' => [
                'host' => $env['SMTP_HOST'] ?? ($phpConfig['smtp']['host'] ?? ''),
                'port' => (int) ($env['SMTP_PORT'] ?? ($phpConfig['smtp']['port'] ?? 465)),
                'encryption' => strtolower((string) ($env['SMTP_ENCRYPTION'] ?? ($phpConfig['smtp']['encryption'] ?? 'ssl'))),
                'user' => $env['SMTP_USER'] ?? ($phpConfig['smtp']['user'] ?? ''),
                'pass' => $env['SMTP_PASS'] ?? ($phpConfig['smtp']['pass'] ?? ''),
                'from_email' => $env['SMTP_FROM_EMAIL'] ?? ($phpConfig['smtp']['from_email'] ?? ''),
                'from_name' => $env['SMTP_FROM_NAME'] ?? ($phpConfig['smtp']['from_name'] ?? 'Hopr Security'),
            ],
            'security' => [
                'trusted_proxies' => $trustedProxies,
            ],
            'admin' => [
                'username' => (string) ($env['ADMIN_USERNAME'] ?? ($phpConfig['admin']['username'] ?? 'admin')),
                'password_hash' => (string) ($env['ADMIN_PASSWORD_HASH'] ?? ($phpConfig['admin']['password_hash'] ?? '')),
                'password' => (string) ($env['ADMIN_PASSWORD'] ?? ($phpConfig['admin']['password'] ?? '')),
            ],
        ]);
    }

    /**
     * @param array<string, mixed> $data
     */
    public static function fromArray(array $data): self
    {
        return new self($data);
    }

    public function get(string $dotKey, mixed $default = null): mixed
    {
        $segments = explode('.', $dotKey);
        $current = $this->data;

        foreach ($segments as $segment) {
            if (!is_array($current) || !array_key_exists($segment, $current)) {
                return $default;
            }
            $current = $current[$segment];
        }

        return $current;
    }

    /**
     * @return array<string, string>
     */
    private static function parseEnvFile(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            return [];
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return [];
        }

        $vars = [];
        foreach ($lines as $line) {
            $trimmed = trim($line);
            if ($trimmed === '' || str_starts_with($trimmed, '#')) {
                continue;
            }

            $eqPos = strpos($trimmed, '=');
            if ($eqPos === false) {
                continue;
            }

            $key = trim(substr($trimmed, 0, $eqPos));
            $value = trim(substr($trimmed, $eqPos + 1));

            if (
                (str_starts_with($value, '"') && str_ends_with($value, '"')) ||
                (str_starts_with($value, "'") && str_ends_with($value, "'"))
            ) {
                $value = substr($value, 1, -1);
            }

            $vars[$key] = $value;
        }

        return $vars;
    }
}
