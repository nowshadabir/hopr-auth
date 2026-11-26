<?php

declare(strict_types=1);

namespace Hopr\Auth\Mail;

interface MailerInterface
{
    public function sendOtp(string $toEmail, string $toName, string $otp): void;
}
