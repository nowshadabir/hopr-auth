<?php

declare(strict_types=1);

namespace Hopr\Auth\Security;

use DateTimeImmutable;
use DateTimeZone;
use PDO;

final class RateLimiter
{
    public function __construct(
        private readonly PDO $pdo,
    ) {
    }

    /**
     * Check and increment a rate limit bucket.
     *
     * @return bool True if allowed, false if rate limit exceeded.
     */
    public function attempt(string $key, int $maxHits, int $windowSeconds, ?DateTimeImmutable $now = null): bool
    {
        $now ??= new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $nowStr = $now->format('Y-m-d H:i:s');
        $cutoffStr = $now->modify("-{$windowSeconds} seconds")->format('Y-m-d H:i:s');

        $this->pdo->beginTransaction();
        try {
            $stmt = $this->pdo->prepare(
                'SELECT id, hits, window_start FROM rate_limits WHERE rate_key = :rate_key LIMIT 1'
            );
            $stmt->execute([':rate_key' => $key]);
            $row = $stmt->fetch();

            if ($row === false) {
                $insert = $this->pdo->prepare(
                    'INSERT INTO rate_limits (rate_key, hits, window_start) VALUES (:rate_key, 1, :window_start)'
                );
                $insert->execute([
                    ':rate_key' => $key,
                    ':window_start' => $nowStr,
                ]);
                $this->pdo->commit();
                return true;
            }

            $windowStart = (string) $row['window_start'];
            $hits = (int) $row['hits'];

            if ($windowStart <= $cutoffStr) {
                $reset = $this->pdo->prepare(
                    'UPDATE rate_limits SET hits = 1, window_start = :window_start WHERE id = :id'
                );
                $reset->execute([
                    ':window_start' => $nowStr,
                    ':id' => (int) $row['id'],
                ]);
                $this->pdo->commit();
                return true;
            }

            if ($hits >= $maxHits) {
                $this->pdo->commit();
                return false;
            }

            $inc = $this->pdo->prepare(
                'UPDATE rate_limits SET hits = hits + 1 WHERE id = :id'
            );
            $inc->execute([':id' => (int) $row['id']]);
            $this->pdo->commit();

            return true;
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }
    }

    /**
     * Enforce both IP and email rate limits for an endpoint.
     */
    public function checkIpAndEmail(
        string $action,
        string $ip,
        ?string $email,
        int $ipMaxHits = 20,
        int $emailMaxHits = 10,
        int $windowSeconds = 900,
        ?DateTimeImmutable $now = null,
    ): bool {
        $ipKey = sprintf('ip:%s:%s', $action, $ip);
        if (!$this->attempt($ipKey, $ipMaxHits, $windowSeconds, $now)) {
            return false;
        }

        if ($email !== null && $email !== '') {
            $emailKey = sprintf('email:%s:%s', $action, hash('sha256', strtolower($email)));
            if (!$this->attempt($emailKey, $emailMaxHits, $windowSeconds, $now)) {
                return false;
            }
        }

        return true;
    }
}
