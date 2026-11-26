<?php

declare(strict_types=1);

namespace Hopr\Auth;

use PDO;

final class Database
{
    public static function connect(Config $config): PDO
    {
        $host = (string) $config->get('db.host');
        $port = (int) $config->get('db.port', 3306);
        $name = (string) $config->get('db.name');
        $user = (string) $config->get('db.user');
        $pass = (string) $config->get('db.pass');

        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $host, $port, $name);

        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);

        $pdo->exec("SET time_zone = '+00:00'");

        return $pdo;
    }
}
