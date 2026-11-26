<?php

declare(strict_types=1);

/**
 * Alternative PHP-array configuration file (if you prefer config.php over .env).
 * Copy to `config/config.php` OUTSIDE public_html.
 * Values in `.env` take precedence if both exist.
 */
return [
    'app' => [
        'env' => 'production',
        'debug' => false,
        'name' => 'Hopr',
        'pepper' => 'CHANGE_ME_TO_A_64_CHAR_RANDOM_HEX_SECRET',
    ],
    'db' => [
        'host' => '127.0.0.1',
        'port' => 3306,
        'name' => 'cpaneluser_hopr_auth',
        'user' => 'cpaneluser_hopr_user',
        'pass' => 'CHANGE_ME_STRONG_DB_PASSWORD',
    ],
    'smtp' => [
        'host' => 'mail.yourdomain.com',
        'port' => 465,
        'encryption' => 'ssl', // 'ssl' or 'tls'
        'user' => 'noreply@yourdomain.com',
        'pass' => 'CHANGE_ME_SMTP_PASSWORD',
        'from_email' => 'noreply@yourdomain.com',
        'from_name' => 'Hopr Security',
    ],
    'security' => [
        'trusted_proxies' => [],
    ],
];
