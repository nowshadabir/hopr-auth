<?php

declare(strict_types=1);

namespace Hopr\Auth\Auth;

use DateTimeImmutable;
use DateTimeZone;
use Hopr\Auth\Http\Response;
use Hopr\Auth\Mail\MailerInterface;
use Hopr\Auth\Security\RateLimiter;
use Hopr\Auth\Security\Validator;
use PDO;

final class AuthService
{
    private const OTP_TTL_SECONDS = 600;       // 10 minutes
    private const OTP_MAX_ATTEMPTS = 5;
    private const OTP_COOLDOWN_SECONDS = 60;
    private const SESSION_TTL_DAYS = 30;

    // Precomputed dummy Argon2/Bcrypt hash for constant-time login failure when user does not exist
    private const DUMMY_HASH = '$2y$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi';

    public function __construct(
        private readonly PDO $pdo,
        private readonly MailerInterface $mailer,
        private readonly RateLimiter $rateLimiter,
        private readonly string $pepper,
        private readonly ?DateTimeImmutable $fixedNow = null,
    ) {
    }

    /**
     * POST /auth/signup
     *
     * @param array<string, mixed> $body
     */
    public function signup(array $body, string $clientIp): Response
    {
        $rawEmail = Validator::normalizeEmail($body['email'] ?? null);

        if (!$this->rateLimiter->checkIpAndEmail('signup', $clientIp, $rawEmail, 20, 10, 900, $this->now())) {
            return $this->rateLimitedResponse();
        }

        $name = Validator::sanitizeName($body['name'] ?? null);
        $phone = Validator::sanitizePhone($body['phone'] ?? null);
        $password = Validator::validatePassword($body['password'] ?? null);

        if ($name === null || $phone === null || $rawEmail === null || $password === null) {
            return Response::error(400, 'INVALID_INPUT', 'Please provide valid name, phone, email, and password (min 8 characters).');
        }

        $now = $this->now();
        $nowStr = $now->format('Y-m-d H:i:s');
        $passwordHash = $this->hashPassword($password);

        $stmt = $this->pdo->prepare(
            'SELECT id, email_verified FROM users WHERE email = :email LIMIT 1'
        );
        $stmt->execute([':email' => $rawEmail]);
        $existing = $stmt->fetch();

        if ($existing !== false && (int) $existing['email_verified'] === 1) {
            return Response::error(409, 'EMAIL_EXISTS', 'An account with this email already exists.');
        }

        $this->pdo->beginTransaction();
        try {
            if ($existing !== false) {
                $userId = (int) $existing['id'];

                if ($this->isInResendCooldown($userId, $now)) {
                    $this->pdo->rollBack();
                    return $this->rateLimitedResponse('Please wait 60 seconds before requesting a new verification code.', 60);
                }

                $update = $this->pdo->prepare(
                    'UPDATE users SET name = :name, phone = :phone, password_hash = :password_hash WHERE id = :id'
                );
                $update->execute([
                    ':name' => $name,
                    ':phone' => $phone,
                    ':password_hash' => $passwordHash,
                    ':id' => $userId,
                ]);
            } else {
                $insert = $this->pdo->prepare(
                    'INSERT INTO users (name, phone, email, password_hash, email_verified, subscription_status, created_at)
                     VALUES (:name, :phone, :email, :password_hash, 0, :status, :created_at)'
                );
                $insert->execute([
                    ':name' => $name,
                    ':phone' => $phone,
                    ':email' => $rawEmail,
                    ':password_hash' => $passwordHash,
                    ':status' => 'active',
                    ':created_at' => $nowStr,
                ]);
                $userId = (int) $this->pdo->lastInsertId();
            }

            $otp = $this->issueOtp($userId, $now);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        $this->mailer->sendOtp($rawEmail, $name, $otp);

        return Response::json(200, [
            'ok' => true,
            'message' => 'Verification code sent to your email.',
        ]);
    }

    /**
     * POST /auth/verify-otp
     *
     * @param array<string, mixed> $body
     */
    public function verifyOtp(array $body, string $clientIp): Response
    {
        $email = Validator::normalizeEmail($body['email'] ?? null);

        if (!$this->rateLimiter->checkIpAndEmail('verify_otp', $clientIp, $email, 20, 10, 900, $this->now())) {
            return $this->rateLimitedResponse();
        }

        $otp = Validator::validateOtp($body['otp'] ?? null);
        $deviceName = Validator::sanitizeDeviceName($body['device_name'] ?? null);

        if ($email === null || $otp === null) {
            return Response::error(400, 'INVALID_OTP', 'Invalid or expired verification code.');
        }

        $now = $this->now();
        $nowStr = $now->format('Y-m-d H:i:s');

        $userStmt = $this->pdo->prepare(
            'SELECT id, name, email, phone, subscription_status FROM users WHERE email = :email LIMIT 1'
        );
        $userStmt->execute([':email' => $email]);
        $user = $userStmt->fetch();

        if ($user === false) {
            return Response::error(400, 'INVALID_OTP', 'Invalid verification code.');
        }

        $userId = (int) $user['id'];

        $otpStmt = $this->pdo->prepare(
            'SELECT id, otp_hash, expires_at, attempts
             FROM email_otps
             WHERE user_id = :user_id AND used_at IS NULL
             ORDER BY id DESC
             LIMIT 1'
        );
        $otpStmt->execute([':user_id' => $userId]);
        $otpRow = $otpStmt->fetch();

        if ($otpRow === false) {
            return Response::error(400, 'INVALID_OTP', 'Invalid verification code.');
        }

        $otpId = (int) $otpRow['id'];
        $attempts = (int) $otpRow['attempts'];

        if ($attempts >= self::OTP_MAX_ATTEMPTS) {
            $this->markOtpUsed($otpId, $nowStr);
            return Response::error(400, 'INVALID_OTP', 'Verification code has been invalidated due to too many failed attempts.');
        }

        if ((string) $otpRow['expires_at'] <= $nowStr) {
            $this->markOtpUsed($otpId, $nowStr);
            return Response::error(400, 'OTP_EXPIRED', 'Verification code has expired. Please request a new one.');
        }

        $expectedHash = (string) $otpRow['otp_hash'];
        $providedHash = $this->hashOtp($otp);

        if (!hash_equals($expectedHash, $providedHash)) {
            $newAttempts = $attempts + 1;
            if ($newAttempts >= self::OTP_MAX_ATTEMPTS) {
                $upd = $this->pdo->prepare(
                    'UPDATE email_otps SET attempts = :attempts, used_at = :used_at WHERE id = :id'
                );
                $upd->execute([
                    ':attempts' => $newAttempts,
                    ':used_at' => $nowStr,
                    ':id' => $otpId,
                ]);
            } else {
                $upd = $this->pdo->prepare(
                    'UPDATE email_otps SET attempts = :attempts WHERE id = :id'
                );
                $upd->execute([
                    ':attempts' => $newAttempts,
                    ':id' => $otpId,
                ]);
            }

            return Response::error(400, 'INVALID_OTP', 'Invalid verification code.');
        }

        $this->pdo->beginTransaction();
        try {
            $this->markOtpUsed($otpId, $nowStr);

            $verifyUser = $this->pdo->prepare(
                'UPDATE users SET email_verified = 1 WHERE id = :id'
            );
            $verifyUser->execute([':id' => $userId]);

            $token = $this->createSession($userId, $deviceName, $now);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        return Response::json(200, [
            'ok' => true,
            'token' => $token,
            'user' => $this->formatUser($user),
        ]);
    }

    /**
     * POST /auth/resend-otp
     *
     * @param array<string, mixed> $body
     */
    public function resendOtp(array $body, string $clientIp): Response
    {
        $email = Validator::normalizeEmail($body['email'] ?? null);

        if (!$this->rateLimiter->checkIpAndEmail('resend_otp', $clientIp, $email, 15, 5, 900, $this->now())) {
            return $this->rateLimitedResponse();
        }

        if ($email === null) {
            return Response::error(400, 'INVALID_INPUT', 'Please provide a valid email address.');
        }

        $stmt = $this->pdo->prepare(
            'SELECT id, name, email_verified FROM users WHERE email = :email LIMIT 1'
        );
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();

        // Prevent email enumeration: return 200 even if not found or already verified
        if ($user === false || (int) $user['email_verified'] === 1) {
            return Response::json(200, [
                'ok' => true,
                'message' => 'A new verification code was sent.',
            ]);
        }

        $userId = (int) $user['id'];
        $now = $this->now();

        if ($this->isInResendCooldown($userId, $now)) {
            return $this->rateLimitedResponse('Please wait 60 seconds before requesting a new verification code.', 60);
        }

        $this->pdo->beginTransaction();
        try {
            $otp = $this->issueOtp($userId, $now);
            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        $this->mailer->sendOtp($email, (string) $user['name'], $otp);

        return Response::json(200, [
            'ok' => true,
            'message' => 'A new verification code was sent.',
        ]);
    }

    /**
     * POST /auth/login
     *
     * @param array<string, mixed> $body
     */
    public function login(array $body, string $clientIp): Response
    {
        $email = Validator::normalizeEmail($body['email'] ?? null);

        if (!$this->rateLimiter->checkIpAndEmail('login', $clientIp, $email, 20, 10, 900, $this->now())) {
            return $this->rateLimitedResponse();
        }

        $password = is_string($body['password'] ?? null) ? $body['password'] : '';
        $deviceName = Validator::sanitizeDeviceName($body['device_name'] ?? null);

        if ($email === null || $password === '' || strlen($password) > 128) {
            return Response::error(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
        }

        $stmt = $this->pdo->prepare(
            'SELECT id, name, phone, email, password_hash, email_verified, subscription_status, subscription_expires_at
             FROM users
             WHERE email = :email
             LIMIT 1'
        );
        $stmt->execute([':email' => $email]);
        $user = $stmt->fetch();

        if ($user === false) {
            password_verify($password, self::DUMMY_HASH);
            return Response::error(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
        }

        if (!password_verify($password, (string) $user['password_hash'])) {
            return Response::error(401, 'INVALID_CREDENTIALS', 'Invalid email or password.');
        }

        if ((int) $user['email_verified'] === 0) {
            return Response::error(403, 'EMAIL_NOT_VERIFIED', 'Please verify your email first.');
        }

        $now = $this->now();
        if (!$this->isSubscriptionActive($user, $now)) {
            return Response::error(403, 'SUBSCRIPTION_REQUIRED', 'Active subscription required.');
        }

        $token = $this->createSession((int) $user['id'], $deviceName, $now);

        return Response::json(200, [
            'ok' => true,
            'token' => $token,
            'user' => $this->formatUser($user),
        ]);
    }

    /**
     * GET /auth/me
     */
    public function me(?string $bearerToken): Response
    {
        if ($bearerToken === null) {
            return Response::error(401, 'UNAUTHORIZED', 'Missing or invalid authorization token.');
        }

        $now = $this->now();
        $nowStr = $now->format('Y-m-d H:i:s');
        $tokenHash = hash('sha256', $bearerToken);

        $stmt = $this->pdo->prepare(
            'SELECT u.id, u.name, u.email, u.phone, u.email_verified, u.subscription_status, u.subscription_expires_at
             FROM user_sessions s
             INNER JOIN users u ON u.id = s.user_id
             WHERE s.token_hash = :token_hash
               AND s.revoked_at IS NULL
               AND s.expires_at > :now
             LIMIT 1'
        );
        $stmt->execute([
            ':token_hash' => $tokenHash,
            ':now' => $nowStr,
        ]);
        $user = $stmt->fetch();

        if ($user === false || (int) $user['email_verified'] === 0) {
            return Response::error(401, 'UNAUTHORIZED', 'Session is invalid or expired.');
        }

        if (!$this->isSubscriptionActive($user, $now)) {
            return Response::error(403, 'SUBSCRIPTION_REQUIRED', 'Active subscription required.');
        }

        return Response::json(200, [
            'ok' => true,
            'user' => $this->formatUser($user),
        ]);
    }

    /**
     * POST /auth/logout
     */
    public function logout(?string $bearerToken): Response
    {
        if ($bearerToken === null) {
            return Response::error(401, 'UNAUTHORIZED', 'Missing or invalid authorization token.');
        }

        $nowStr = $this->now()->format('Y-m-d H:i:s');
        $tokenHash = hash('sha256', $bearerToken);

        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions
             SET revoked_at = :revoked_at
             WHERE token_hash = :token_hash AND revoked_at IS NULL'
        );
        $stmt->execute([
            ':revoked_at' => $nowStr,
            ':token_hash' => $tokenHash,
        ]);

        if ($stmt->rowCount() === 0) {
            return Response::error(401, 'UNAUTHORIZED', 'Session is invalid or already revoked.');
        }

        return Response::json(200, [
            'ok' => true,
        ]);
    }

    private function hashPassword(string $password): string
    {
        $algo = defined('PASSWORD_ARGON2ID') ? PASSWORD_ARGON2ID : PASSWORD_BCRYPT;
        return password_hash($password, $algo);
    }

    private function hashOtp(string $otp): string
    {
        return hash_hmac('sha256', $otp, $this->pepper);
    }

    private function isInResendCooldown(int $userId, DateTimeImmutable $now): bool
    {
        $cutoff = $now->modify('-' . self::OTP_COOLDOWN_SECONDS . ' seconds')->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare(
            'SELECT id FROM email_otps WHERE user_id = :user_id AND created_at > :cutoff LIMIT 1'
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':cutoff' => $cutoff,
        ]);

        return $stmt->fetch() !== false;
    }

    private function issueOtp(int $userId, DateTimeImmutable $now): string
    {
        $nowStr = $now->format('Y-m-d H:i:s');
        $expiresStr = $now->modify('+' . self::OTP_TTL_SECONDS . ' seconds')->format('Y-m-d H:i:s');

        // Invalidate any previous unused OTPs for this user
        $invalidate = $this->pdo->prepare(
            'UPDATE email_otps SET used_at = :used_at WHERE user_id = :user_id AND used_at IS NULL'
        );
        $invalidate->execute([
            ':used_at' => $nowStr,
            ':user_id' => $userId,
        ]);

        $otp = (string) random_int(100000, 999999);
        $otpHash = $this->hashOtp($otp);

        $insert = $this->pdo->prepare(
            'INSERT INTO email_otps (user_id, otp_hash, expires_at, attempts, created_at)
             VALUES (:user_id, :otp_hash, :expires_at, 0, :created_at)'
        );
        $insert->execute([
            ':user_id' => $userId,
            ':otp_hash' => $otpHash,
            ':expires_at' => $expiresStr,
            ':created_at' => $nowStr,
        ]);

        return $otp;
    }

    private function markOtpUsed(int $otpId, string $nowStr): void
    {
        $stmt = $this->pdo->prepare(
            'UPDATE email_otps SET used_at = :used_at WHERE id = :id'
        );
        $stmt->execute([
            ':used_at' => $nowStr,
            ':id' => $otpId,
        ]);
    }

    private function createSession(int $userId, string $deviceName, DateTimeImmutable $now): string
    {
        $token = bin2hex(random_bytes(32));
        $tokenHash = hash('sha256', $token);
        $nowStr = $now->format('Y-m-d H:i:s');
        $expiresStr = $now->modify('+' . self::SESSION_TTL_DAYS . ' days')->format('Y-m-d H:i:s');

        $stmt = $this->pdo->prepare(
            'INSERT INTO user_sessions (user_id, token_hash, device_name, expires_at, created_at)
             VALUES (:user_id, :token_hash, :device_name, :expires_at, :created_at)'
        );
        $stmt->execute([
            ':user_id' => $userId,
            ':token_hash' => $tokenHash,
            ':device_name' => $deviceName,
            ':expires_at' => $expiresStr,
            ':created_at' => $nowStr,
        ]);

        return $token;
    }

    /**
     * @param array<string, mixed> $user
     */
    private function isSubscriptionActive(array $user, DateTimeImmutable $now): bool
    {
        $status = (string) ($user['subscription_status'] ?? '');
        if (in_array($status, ['expired', 'suspended'], true)) {
            return false;
        }

        $expiresAt = $user['subscription_expires_at'] ?? null;
        if (is_string($expiresAt) && $expiresAt !== '') {
            if ($expiresAt <= $now->format('Y-m-d H:i:s')) {
                return false;
            }
        }

        return in_array($status, ['active', 'trial'], true);
    }

    /**
     * @param array<string, mixed> $user
     * @return array<string, mixed>
     */
    private function formatUser(array $user): array
    {
        return [
            'id' => (int) $user['id'],
            'name' => (string) $user['name'],
            'email' => (string) $user['email'],
            'phone' => (string) $user['phone'],
            'subscription_status' => (string) $user['subscription_status'],
        ];
    }

    private function rateLimitedResponse(
        string $message = 'Too many requests. Please try again later.',
        int $retryAfter = 900,
    ): Response {
        return Response::error(429, 'RATE_LIMITED', $message, [
            'Retry-After' => (string) $retryAfter,
        ]);
    }

    private function now(): DateTimeImmutable
    {
        return $this->fixedNow ?? new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
