<?php

declare(strict_types=1);

namespace Hopr\Auth\Tests;

use DateTimeImmutable;
use DateTimeZone;
use Hopr\Auth\App;
use Hopr\Auth\Auth\AuthService;
use Hopr\Auth\Config;
use Hopr\Auth\Http\Request;
use Hopr\Auth\Mail\MailerInterface;
use Hopr\Auth\Security\RateLimiter;
use PDO;
use PHPUnit\Framework\TestCase;

final class FakeMailer implements MailerInterface
{
    /** @var array<int, array{email: string, name: string, otp: string}> */
    public array $sent = [];

    public function sendOtp(string $toEmail, string $toName, string $otp): void
    {
        $this->sent[] = [
            'email' => $toEmail,
            'name' => $toName,
            'otp' => $otp,
        ];
    }

    public function lastOtp(): ?string
    {
        if ($this->sent === []) {
            return null;
        }
        return $this->sent[array_key_last($this->sent)]['otp'];
    }
}

final class AuthApiTest extends TestCase
{
    private const PEPPER = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';

    private PDO $pdo;
    private FakeMailer $mailer;
    private RateLimiter $rateLimiter;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:', null, null, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);

        $this->pdo->exec('
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 0,
                subscription_status TEXT NOT NULL DEFAULT "active",
                subscription_expires_at TEXT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE email_otps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                otp_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                used_at TEXT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                device_name TEXT NOT NULL DEFAULT "Unknown Device",
                expires_at TEXT NOT NULL,
                revoked_at TEXT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rate_key TEXT NOT NULL UNIQUE,
                hits INTEGER NOT NULL DEFAULT 0,
                window_start TEXT NOT NULL
            );
        ');

        $this->mailer = new FakeMailer();
        $this->rateLimiter = new RateLimiter($this->pdo);
    }

    private function makeApp(?DateTimeImmutable $now = null): App
    {
        $service = new AuthService(
            $this->pdo,
            $this->mailer,
            $this->rateLimiter,
            self::PEPPER,
            $now ?? new DateTimeImmutable('2026-11-27 00:00:00', new DateTimeZone('UTC')),
        );
        return new App($service);
    }

    /**
     * @param array<string, mixed> $body
     * @param array<string, string> $headers
     */
    private function req(string $method, string $path, array $body = [], array $headers = [], string $ip = '203.0.113.10'): Request
    {
        return new Request($method, $path, $body, $headers, $ip);
    }

    public function testFullSignupVerifyMeLoginLogoutFlow(): void
    {
        $t0 = new DateTimeImmutable('2026-11-27 00:00:00', new DateTimeZone('UTC'));
        $app = $this->makeApp($t0);

        // 1. Signup
        $res = $app->handle($this->req('POST', '/auth/signup', [
            'name' => 'Alice Hopper',
            'phone' => '+1 555-0100',
            'email' => 'Alice@Example.com',
            'password' => 'SuperSecret123!',
        ]));
        $this->assertSame(200, $res->status);
        $this->assertTrue($res->data['ok']);
        $this->assertCount(1, $this->mailer->sent);

        $otp = $this->mailer->lastOtp();
        $this->assertNotNull($otp);
        $this->assertMatchesRegularExpression('/^\d{6}$/', $otp);

        // Ensure OTP is stored hashed with HMAC-SHA256, not plaintext
        $otpRow = $this->pdo->query('SELECT otp_hash FROM email_otps LIMIT 1')->fetch();
        $this->assertNotFalse($otpRow);
        $this->assertNotSame($otp, $otpRow['otp_hash']);
        $this->assertSame(hash_hmac('sha256', $otp, self::PEPPER), $otpRow['otp_hash']);

        // Ensure password is hashed with Argon2id (or Bcrypt fallback)
        $userRow = $this->pdo->query('SELECT password_hash FROM users LIMIT 1')->fetch();
        $this->assertNotFalse($userRow);
        $this->assertTrue(password_verify('SuperSecret123!', (string) $userRow['password_hash']));

        // 2. Login before verification -> 403 EMAIL_NOT_VERIFIED
        $loginUnverified = $app->handle($this->req('POST', '/auth/login', [
            'email' => 'alice@example.com',
            'password' => 'SuperSecret123!',
            'device_name' => 'MacBook Pro',
        ]));
        $this->assertSame(403, $loginUnverified->status);
        $this->assertSame('EMAIL_NOT_VERIFIED', $loginUnverified->data['code']);

        // 3. Verify OTP -> 200 + 64-char hex token
        $verify = $app->handle($this->req('POST', '/auth/verify-otp', [
            'email' => 'alice@example.com',
            'otp' => $otp,
            'device_name' => 'MacBook Pro',
        ]));
        $this->assertSame(200, $verify->status);
        $this->assertTrue($verify->data['ok']);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $verify->data['token']);
        $this->assertSame('alice@example.com', $verify->data['user']['email']);
        $this->assertSame('active', $verify->data['user']['subscription_status']);

        $token = $verify->data['token'];

        // Ensure only sha256(token) is stored in user_sessions
        $sessRow = $this->pdo->query('SELECT token_hash FROM user_sessions LIMIT 1')->fetch();
        $this->assertNotFalse($sessRow);
        $this->assertSame(hash('sha256', $token), $sessRow['token_hash']);

        // 4. Duplicate signup for verified user -> 409 EMAIL_EXISTS
        $dup = $app->handle($this->req('POST', '/auth/signup', [
            'name' => 'Alice',
            'phone' => '+1 555-0100',
            'email' => 'alice@example.com',
            'password' => 'AnotherPass123!',
        ]));
        $this->assertSame(409, $dup->status);
        $this->assertSame('EMAIL_EXISTS', $dup->data['code']);

        // 5. GET /auth/me with Bearer token
        $me = $app->handle($this->req('GET', '/auth/me', [], [
            'authorization' => 'Bearer ' . $token,
        ]));
        $this->assertSame(200, $me->status);
        $this->assertSame('Alice Hopper', $me->data['user']['name']);

        // 6. POST /auth/logout
        $logout = $app->handle($this->req('POST', '/auth/logout', [], [
            'authorization' => 'Bearer ' . $token,
        ]));
        $this->assertSame(200, $logout->status);
        $this->assertTrue($logout->data['ok']);

        // 7. GET /auth/me after logout -> 401
        $meAfterLogout = $app->handle($this->req('GET', '/auth/me', [], [
            'authorization' => 'Bearer ' . $token,
        ]));
        $this->assertSame(401, $meAfterLogout->status);

        // 8. POST /auth/login -> 200
        $login = $app->handle($this->req('POST', '/auth/login', [
            'email' => 'alice@example.com',
            'password' => 'SuperSecret123!',
            'device_name' => 'Windows Desktop',
        ]));
        $this->assertSame(200, $login->status);
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $login->data['token']);
    }

    public function testOtpExpirationAndMaxAttemptsAndCooldown(): void
    {
        $t0 = new DateTimeImmutable('2026-11-27 00:00:00', new DateTimeZone('UTC'));
        $app0 = $this->makeApp($t0);

        $app0->handle($this->req('POST', '/auth/signup', [
            'name' => 'Bob',
            'phone' => '+15550101',
            'email' => 'bob@example.com',
            'password' => 'Password123!',
        ]));
        $otp1 = $this->mailer->lastOtp();

        // Resend within 60s -> 429 RATE_LIMITED
        $cooldown = $app0->handle($this->req('POST', '/auth/resend-otp', [
            'email' => 'bob@example.com',
        ]));
        $this->assertSame(429, $cooldown->status);
        $this->assertSame('RATE_LIMITED', $cooldown->data['code']);

        // Resend after 61s -> 200 + new OTP
        $t1 = $t0->modify('+61 seconds');
        $app1 = $this->makeApp($t1);
        $resend = $app1->handle($this->req('POST', '/auth/resend-otp', [
            'email' => 'bob@example.com',
        ]));
        $this->assertSame(200, $resend->status);
        $otp2 = $this->mailer->lastOtp();
        $this->assertNotNull($otp2);

        // Old OTP must be invalidated
        $oldVerify = $app1->handle($this->req('POST', '/auth/verify-otp', [
            'email' => 'bob@example.com',
            'otp' => $otp1 === $otp2 ? '000000' : $otp1,
            'device_name' => 'Test',
        ]));
        $this->assertSame(400, $oldVerify->status);
        $this->assertSame('INVALID_OTP', $oldVerify->data['code']);

        // 4 more failed attempts -> 5th invalidates the OTP completely
        for ($i = 0; $i < 4; $i++) {
            $bad = $app1->handle($this->req('POST', '/auth/verify-otp', [
                'email' => 'bob@example.com',
                'otp' => '000000',
                'device_name' => 'Test',
            ]));
            $this->assertSame(400, $bad->status);
        }

        // Now even the real otp2 must fail because 5 attempts were exhausted
        $afterExhausted = $app1->handle($this->req('POST', '/auth/verify-otp', [
            'email' => 'bob@example.com',
            'otp' => $otp2,
            'device_name' => 'Test',
        ]));
        $this->assertSame(400, $afterExhausted->status);
        $this->assertSame('INVALID_OTP', $afterExhausted->data['code']);

        // Request new OTP after another 61s, then let it expire (>10 min)
        $t2 = $t1->modify('+61 seconds');
        $app2 = $this->makeApp($t2);
        $app2->handle($this->req('POST', '/auth/resend-otp', [
            'email' => 'bob@example.com',
        ]));
        $otp3 = $this->mailer->lastOtp();

        $tExpired = $t2->modify('+11 minutes');
        $appExpired = $this->makeApp($tExpired);
        $expiredRes = $appExpired->handle($this->req('POST', '/auth/verify-otp', [
            'email' => 'bob@example.com',
            'otp' => $otp3,
            'device_name' => 'Test',
        ]));
        $this->assertSame(400, $expiredRes->status);
        $this->assertSame('OTP_EXPIRED', $expiredRes->data['code']);
    }

    public function testSubscriptionEnforcementAndLoginErrors(): void
    {
        $t0 = new DateTimeImmutable('2026-11-27 00:00:00', new DateTimeZone('UTC'));
        $app = $this->makeApp($t0);

        $app->handle($this->req('POST', '/auth/signup', [
            'name' => 'Carol',
            'phone' => '+15550102',
            'email' => 'carol@example.com',
            'password' => 'Password123!',
        ]));
        $otp = $this->mailer->lastOtp();
        $verify = $app->handle($this->req('POST', '/auth/verify-otp', [
            'email' => 'carol@example.com',
            'otp' => $otp,
            'device_name' => 'Linux',
        ]));
        $token = $verify->data['token'];

        // Wrong password -> 401 generic message
        $badPass = $app->handle($this->req('POST', '/auth/login', [
            'email' => 'carol@example.com',
            'password' => 'WrongPassword',
        ]));
        $this->assertSame(401, $badPass->status);
        $this->assertSame('INVALID_CREDENTIALS', $badPass->data['code']);
        $this->assertSame('Invalid email or password.', $badPass->data['message']);

        // Unknown email -> same 401 generic message
        $unknown = $app->handle($this->req('POST', '/auth/login', [
            'email' => 'nobody@example.com',
            'password' => 'WrongPassword',
        ]));
        $this->assertSame(401, $unknown->status);
        $this->assertSame('INVALID_CREDENTIALS', $unknown->data['code']);
        $this->assertSame('Invalid email or password.', $unknown->data['message']);

        // Mark subscription expired -> 403 SUBSCRIPTION_REQUIRED on /auth/login and /auth/me
        $this->pdo->exec("UPDATE users SET subscription_status = 'expired' WHERE email = 'carol@example.com'");

        $loginExpired = $app->handle($this->req('POST', '/auth/login', [
            'email' => 'carol@example.com',
            'password' => 'Password123!',
        ]));
        $this->assertSame(403, $loginExpired->status);
        $this->assertSame('SUBSCRIPTION_REQUIRED', $loginExpired->data['code']);

        $meExpired = $app->handle($this->req('GET', '/auth/me', [], [
            'authorization' => 'Bearer ' . $token,
        ]));
        $this->assertSame(403, $meExpired->status);
        $this->assertSame('SUBSCRIPTION_REQUIRED', $meExpired->data['code']);
    }

    public function testRateLimitingReturns429(): void
    {
        $t0 = new DateTimeImmutable('2026-11-27 00:00:00', new DateTimeZone('UTC'));
        $app = $this->makeApp($t0);

        for ($i = 0; $i < 10; $i++) {
            $res = $app->handle($this->req('POST', '/auth/login', [
                'email' => 'ratelimit@example.com',
                'password' => 'WrongPass123',
            ], [], '198.51.100.' . ($i + 1)));
            $this->assertSame(401, $res->status);
        }

        // 11th request for same email -> 429 RATE_LIMITED
        $limited = $app->handle($this->req('POST', '/auth/login', [
            'email' => 'ratelimit@example.com',
            'password' => 'WrongPass123',
        ], [], '198.51.100.99'));
        $this->assertSame(429, $limited->status);
        $this->assertSame('RATE_LIMITED', $limited->data['code']);
    }

    public function testConfigRejectsPlaceholderPepper(): void
    {
        $this->expectException(\RuntimeException::class);
        Config::load(dirname(__DIR__));
    }
}
