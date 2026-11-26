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
        public readonly ?string $rawBody = null,
        public readonly string $contentType = 'application/json; charset=utf-8',
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

    /**
     * @param array<string, string> $headers
     */
    public static function html(int $status, string $html, array $headers = []): self
    {
        return new self($status, [], $headers, $html, 'text/html; charset=utf-8');
    }

    /**
     * @param array<string, string> $headers
     */
    public static function redirect(string $location, array $headers = []): self
    {
        $headers['Location'] = $location;
        return new self(302, [], $headers, '');
    }

    public function send(): void
    {
        http_response_code($this->status);
        header('Content-Type: ' . $this->contentType);
        header('X-Content-Type-Options: nosniff');
        header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

        foreach ($this->headers as $name => $value) {
            header($name . ': ' . $value);
        }

        if ($this->rawBody !== null) {
            echo $this->rawBody;
            return;
        }

        echo json_encode($this->data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }
}
