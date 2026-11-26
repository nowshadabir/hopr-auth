<?php

declare(strict_types=1);

namespace Hopr\Auth\Security;

final class Validator
{
    public static function sanitizeName(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $clean = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? '');
        $len = mb_strlen($clean, 'UTF-8');
        if ($len < 1 || $len > 120) {
            return null;
        }
        return $clean;
    }

    public static function sanitizePhone(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $clean = trim(preg_replace('/\s+/', ' ', $value) ?? '');
        if ($clean === '' || strlen($clean) < 5 || strlen($clean) > 32) {
            return null;
        }
        if (preg_match('/^[+0-9()\-\s]+$/', $clean) !== 1) {
            return null;
        }
        return $clean;
    }

    public static function normalizeEmail(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $clean = strtolower(trim($value));
        if ($clean === '' || strlen($clean) > 190) {
            return null;
        }
        if (filter_var($clean, FILTER_VALIDATE_EMAIL) === false) {
            return null;
        }
        return $clean;
    }

    public static function validatePassword(mixed $value): ?string
    {
        if (!is_string($value)) {
            return null;
        }
        $len = strlen($value);
        if ($len < 8 || $len > 128) {
            return null;
        }
        return $value;
    }

    public static function validateOtp(mixed $value): ?string
    {
        if (!is_string($value) && !is_int($value)) {
            return null;
        }
        $otp = trim((string) $value);
        if (preg_match('/^\d{6}$/', $otp) !== 1) {
            return null;
        }
        return $otp;
    }

    public static function sanitizeDeviceName(mixed $value): string
    {
        if (!is_string($value)) {
            return 'Unknown Device';
        }
        $clean = trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $value) ?? '');
        if ($clean === '') {
            return 'Unknown Device';
        }
        return mb_substr($clean, 0, 100, 'UTF-8');
    }
}
