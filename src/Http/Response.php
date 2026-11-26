<?php

declare(strict_types=1);

namespace Hopr\Auth\Http;

final class Response
{
    /**
     * @param array<string, mixed> $data
     * @param array<string, string> $headers
     */
    public function __construct(
        public readonly int $status,
        public readonly array $data,
        public readonly array $headers = [],
    ) {
    }

    /**
     * @param array<string, mixed> $data
     * @param array<string, string> $headers
     */
    public static function json(int $status, array $data, array $headers = []): self
    {
        return new self($status, $data, $headers);
    }

    /**
     * @param array<string, string> $headers
     */
    public static function error(int $status, string $code, string $message, array $headers = []): self
    {
        return new self($status, [
            'ok' => false,
            'code' => $code,
            'message' => $message,
        ], $headers);
    }

    public function send(): void
    {
        http_response_code($this->status);
        header('Content-Type: application/json; charset=utf-8');
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

        foreach ($this->headers as $name => $value) {
            header($name . ': ' . $value);
        }

        echo json_encode($this->data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
