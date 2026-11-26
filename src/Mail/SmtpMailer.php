<?php

declare(strict_types=1);

namespace Hopr\Auth\Mail;

use Hopr\Auth\Config;
use PHPMailer\PHPMailer\PHPMailer;
use RuntimeException;

final class SmtpMailer implements MailerInterface
{
    public function __construct(
        private readonly Config $config,
    ) {
    }

    public function sendOtp(string $toEmail, string $toName, string $otp): void
    {
        $mail = new PHPMailer(true);

        $appName = (string) $this->config->get('app.name', 'Hopr');
        $encryption = (string) $this->config->get('smtp.encryption', 'ssl');

        $mail->isSMTP();
        $mail->Host = (string) $this->config->get('smtp.host');
        $mail->Port = (int) $this->config->get('smtp.port', 465);
        $mail->SMTPAuth = true;
        $mail->Username = (string) $this->config->get('smtp.user');
        $mail->Password = (string) $this->config->get('smtp.pass');
        $mail->SMTPSecure = $encryption === 'tls'
            ? PHPMailer::ENCRYPTION_STARTTLS
            : PHPMailer::ENCRYPTION_SMTPS;
        $mail->CharSet = PHPMailer::CHARSET_UTF8;
        $mail->Timeout = 15;

        $fromEmail = (string) $this->config->get('smtp.from_email');
        $fromName = (string) $this->config->get('smtp.from_name', $appName . ' Security');

        $mail->setFrom($fromEmail, $fromName);
        $mail->addAddress($toEmail, $toName);

        $safeName = htmlspecialchars($toName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $safeOtp = htmlspecialchars($otp, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        $safeApp = htmlspecialchars($appName, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');

        $mail->isHTML(true);
        $mail->Subject = "{$appName} Verification Code: {$otp}";
        $mail->Body = <<<HTML
<!DOCTYPE html>
<html lang="en">
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background:#f6f8fa; padding:24px; color:#111827;">
  <div style="max-width:480px; margin:0 auto; background:#ffffff; border-radius:10px; padding:32px; border:1px solid #e5e7eb;">
    <h2 style="margin:0 0 12px 0; font-size:20px;">Verify your {$safeApp} account</h2>
    <p style="margin:0 0 20px 0; line-height:1.5; color:#374151;">Hi {$safeName},</p>
    <p style="margin:0 0 16px 0; line-height:1.5; color:#374151;">Use the following 6-digit verification code to complete your sign-up:</p>
    <div style="font-size:32px; font-weight:700; letter-spacing:6px; text-align:center; padding:16px; background:#f3f4f6; border-radius:8px; margin:0 0 20px 0; color:#111827;">
      {$safeOtp}
    </div>
    <p style="margin:0 0 8px 0; font-size:13px; color:#6b7280;">This code expires in 10 minutes. Never share it with anyone.</p>
    <p style="margin:0; font-size:13px; color:#6b7280;">If you didn't request this, you can safely ignore this email.</p>
  </div>
</body>
</html>
HTML;
        $mail->AltBody = "Hi {$toName},\n\nYour {$appName} verification code is: {$otp}\n\nThis code expires in 10 minutes. If you didn't request this, ignore this email.\n";

        if (!$mail->send()) {
            throw new RuntimeException('Failed to send verification email.');
        }
    }
}
