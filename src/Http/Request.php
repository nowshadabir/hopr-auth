<?php

declare(strict_types=1);

namespace Hopr\Auth\Http;

use InvalidArgumentException;

final class Request
{
    private const MAX_BODY_BYTES = 65536; // 64 KB

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $headers
     * @param array<string, mixed> $query
     * @param array<string, string> $cookies
     */
    public function __construct(
        public readonly string $method,
        public readonly string $path,
        public readonly array $body,
        public readonly array $headers,
        public readonly string $clientIp,
        public readonly array $query = [],
        public readonly array $cookies = [],
    ) {
    }

    /**
     * @param string[] $trustedProxies
     */
    public static function fromGlobals(array $trustedProxies = []): self
    {
        $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? 'GET'));
        $rawUri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $path = parse_url($rawUri, PHP_URL_PATH);
        $path = is_string($path) ? $path : '/';

        // Support subfolder deployments (e.g. /api/auth/login -> /auth/login)
        $scriptDir = str_replace('\\', '/', dirname((string) ($_SERVER['SCRIPT_NAME'] ?? '')));
        if ($scriptDir !== '/' && $scriptDir !== '.' && str_starts_with($path, $scriptDir)) {
            $path = substr($path, strlen($scriptDir));
            if ($path === '' || $path[0] !== '/') {
                $path = '/' . $path;
            }
        }

        $headers = self::extractHeaders();
        $body = [];

        if (in_array($method, ['POST', 'PUT', 'PATCH'], true)) {
            $contentType = strtolower($headers['content-type'] ?? '');
            $isAdminForm = ($path === '/admin' || str_starts_with($path, '/admin/'))
                && (str_contains($contentType, 'application/x-www-form-urlencoded') || str_contains($contentType, 'multipart/form-data'));

            if ($isAdminForm) {
                $body = $_POST;
            } else {
                $rawBody = file_get_contents('php://input', false, null, 0, self::MAX_BODY_BYTES + 1);
                if ($rawBody !== false && $rawBody !== '') {
                    if (strlen($rawBody) > self::MAX_BODY_BYTES) {
                        throw new InvalidArgumentException('Request body too large.');
                    }
                    $decoded = json_decode($rawBody, true);
                    if (!is_array($decoded)) {
                        throw new InvalidArgumentException('Invalid JSON payload.');
                    }
                    $body = $decoded;
                }
            }
        }

        $clientIp = self::resolveClientIp($trustedProxies);

        $cookies = [];
        foreach ($_COOKIE as $k => $v) {
            if (is_string($k) && is_string($v)) {
                $cookies[$k] = $v;
            }
        }

        return new self($method, $path, $body, $headers, $clientIp, $_GET, $cookies);
    }

    public function getBearerToken(): ?string
    {
        $auth = $this->headers['authorization'] ?? '';
        if ($auth === '') {
            return null;
        }

        if (preg_match('/^Bearer\s+([a-fA-F0-9]{64})$/', trim($auth), $matches) === 1) {
            return strtolower($matches[1]);
        }

        return null;
    }

    /**
     * @return array<string, string>
     */
    private static function extractHeaders(): array
    {
        $headers = [];

        foreach ($_SERVER as $key => $value) {
            if (!is_string($value)) {
                continue;
            }
            if (str_starts_with($key, 'HTTP_')) {
                $name = strtolower(str_replace('_', '-', substr($key, 5)));
                $headers[$name] = $value;
            }
        }

        if (!isset($headers['authorization'])) {
            $redirectAuth = $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? null;
            if (is_string($redirectAuth) && $redirectAuth !== '') {
                $headers['authorization'] = $redirectAuth;
            } elseif (function_exists('apache_request_headers')) {
                $apacheHeaders = apache_request_headers();
                if (is_array($apacheHeaders)) {
                    foreach ($apacheHeaders as $k => $v) {
                        if (strtolower((string) $k) === 'authorization' && is_string($v)) {
                            $headers['authorization'] = $v;
                        }
                    }
                }
            }
        }

        return $headers;
    }

    /**
     * @param string[] $trustedProxies
     */
    private static function resolveClientIp(array $trustedProxies): string
    {
        $remoteAddr = (string) ($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');

        if ($trustedProxies !== [] && in_array($remoteAddr, $trustedProxies, true)) {
            $forwarded = $_SERVER['HTTP_CF_CONNECTING_IP']
                ?? $_SERVER['HTTP_X_FORWARDED_FOR']
                ?? '';

            if (is_string($forwarded) && $forwarded !== '') {
                $firstIp = trim(explode(',', $forwarded)[0]);
                if (filter_var($firstIp, FILTER_VALIDATE_IP) !== false) {
                    return $firstIp;
                }
            }
        }

        return filter_var($remoteAddr, FILTER_VALIDATE_IP) !== false ? $remoteAddr : '0.0.0.0';
    }
}
