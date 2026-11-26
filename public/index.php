<?php

declare(strict_types=1);

use Hopr\Auth\App;
use Hopr\Auth\Auth\AuthService;
use Hopr\Auth\Config;
use Hopr\Auth\Database;
use Hopr\Auth\Http\Request;
use Hopr\Auth\Http\Response;
use Hopr\Auth\Mail\SmtpMailer;
use Hopr\Auth\Security\RateLimiter;

// Base directory is one level above public/ (outside public_html on Namecheap cPanel)
$baseDir = dirname(__DIR__);

require $baseDir . '/vendor/autoload.php';

try {
    $config = Config::load($baseDir);
    $trustedProxies = (array) $config->get('security.trusted_proxies', []);
    $request = Request::fromGlobals($trustedProxies);

    $pdo = Database::connect($config);
    $rateLimiter = new RateLimiter($pdo);
    $mailer = new SmtpMailer($config);
    $authService = new AuthService(
        $pdo,
        $mailer,
        $rateLimiter,
        (string) $config->get('app.pepper'),
    );

    $app = new App($authService);
    $response = $app->handle($request);
    $response->send();
} catch (\InvalidArgumentException $e) {
    Response::error(400, 'BAD_REQUEST', $e->getMessage())->send();
} catch (\Throwable $e) {
    // Log internal error without exposing secrets or stack traces to the client
    error_log('[Hopr Auth API] ' . get_class($e) . ': ' . $e->getMessage());
    Response::error(500, 'INTERNAL_ERROR', 'An unexpected error occurred.')->send();
}
