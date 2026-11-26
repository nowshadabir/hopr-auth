# Hopr Auth API

Production-grade, security-hardened REST Authentication API (PHP 8.2+ with PDO MySQL + PHPMailer) for the **Hopr** desktop application, built for Namecheap cPanel hosting.

---

## Project Structure

```text
Hopr-Auth/                  # Place OUTSIDE public_html (e.g. /home/cpaneluser/hopr-api/)
├── .env.example            # Copy to .env (never commit or place in public_html)
├── .htaccess               # Defense-in-depth deny rules
├── composer.json
├── schema.sql              # MySQL schema (users, email_otps, user_sessions, rate_limits)
├── config/
│   └── config.example.php  # Optional PHP-array config alternative
├── src/
│   ├── App.php             # Router
│   ├── Config.php          # .env / config.php loader
│   ├── Database.php        # Hardened PDO MySQL connector
│   ├── Auth/
│   │   └── AuthService.php # Signup, OTP verify/resend, Login, Me, Logout
│   ├── Http/
│   │   ├── Request.php     # JSON body & Bearer token parser
│   │   └── Response.php    # JSON response + security headers
│   ├── Mail/
│   │   ├── MailerInterface.php
│   │   └── SmtpMailer.php  # Authenticated SMTP (SSL/TLS) via PHPMailer
│   └── Security/
│       ├── RateLimiter.php # IP + email sliding-window rate limiter
│       └── Validator.php   # Input validation & sanitization
├── tests/
│   └── AuthApiTest.php     # PHPUnit integration tests
└── public/                 # Upload contents to public_html/ (or subdomain root)
    ├── .htaccess           # Rewrite rules, Authorization header pass-through, security headers
    └── index.php           # Front controller
```

---

## Step-by-Step Namecheap cPanel Deployment

### 1. Select PHP 8.2+ in cPanel
1. Log in to **Namecheap cPanel**.
2. Open **Select PHP Version** (or **MultiPHP Manager**).
3. Select **PHP 8.2** or **PHP 8.3** for your domain/subdomain.
4. Ensure extensions `pdo_mysql`, `openssl`, `mbstring`, and `sodium` are enabled.

### 2. Create the MySQL Database & Import `schema.sql`
1. In cPanel, open **MySQL® Databases**.
2. Create a new database (e.g., `cpaneluser_hopr_auth`).
3. Create a new MySQL user with a strong generated password (e.g., `cpaneluser_hopr_user`).
4. Under **Add User to Database**, grant **ALL PRIVILEGES** to the user on that database.
5. Open **phpMyAdmin**, select your new database, click **Import**, and upload [`schema.sql`](schema.sql).

### 3. Create an Authenticated SMTP Email Account
1. In cPanel, open **Email Accounts** and create e.g. `noreply@yourdomain.com` (or use Namecheap Private Email).
2. Click **Connect Devices** to note your SMTP settings:
   - **Host**: `mail.yourdomain.com` (or `mail.privateemail.com`)
   - **Port**: `465` (`SMTP_ENCRYPTION=ssl`) or `587` (`SMTP_ENCRYPTION=tls`)

### 4. Upload Files Outside `public_html`
1. In cPanel **File Manager** (or via SFTP/SSH):
   - Create `/home/cpaneluser/hopr-api/`.
   - Upload `src/`, `vendor/`, `config/`, `composer.json`, and `composer.lock` into `/home/cpaneluser/hopr-api/`.
   - *(If deploying without `vendor/`, run `composer install --no-dev --optimize-autoloader` via cPanel Terminal / SSH inside `/home/cpaneluser/hopr-api/`.)*
2. Upload the contents of `public/` (`index.php` and `.htaccess`) into your webroot:
   - Dedicated subdomain (recommended, e.g. `auth.yourdomain.com` -> `/home/cpaneluser/auth.yourdomain.com/`), **OR**
   - `/home/cpaneluser/public_html/` (if dedicated to the API).
3. Update `$baseDir` in your webroot's `index.php` to point to `/home/cpaneluser/hopr-api`:
   ```php
   $baseDir = '/home/cpaneluser/hopr-api';
   ```
   *(If your webroot is `/home/cpaneluser/hopr-api/public`, `dirname(__DIR__)` already resolves to `/home/cpaneluser/hopr-api`.)*

### 5. Configure `.env` Outside Webroot
1. Generate a 64-character hex `APP_PEPPER`:
   ```bash
   php -r "echo bin2hex(random_bytes(32)) . PHP_EOL;"
   ```
2. Create `/home/cpaneluser/hopr-api/.env` from `.env.example`, fill in your DB credentials, SMTP credentials, and `APP_PEPPER`, and set permissions to `0600`:
   ```bash
   chmod 600 /home/cpaneluser/hopr-api/.env
   ```

### 6. Enable HTTPS (AutoSSL)
1. In cPanel, open **SSL/TLS Status** and run **AutoSSL** for `auth.yourdomain.com`.
2. In **Domains**, enable **Force HTTPS Redirect** so all API traffic (passwords, OTPs, Bearer tokens) is encrypted in transit.

### 7. Smoke Test
```bash
curl -s -X POST https://auth.yourdomain.com/auth/signup \
  -H "Content-Type: application/json" \
  -d '{"name":"Test User","phone":"+15550100","email":"you@example.com","password":"StrongPassword123"}'
```

---

## Local Testing

```bash
composer install
./vendor/bin/phpunit
```
