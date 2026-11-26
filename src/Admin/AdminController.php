<?php

declare(strict_types=1);

namespace Hopr\Auth\Admin;

use DateTimeImmutable;
use DateTimeZone;
use Hopr\Auth\Auth\AuthService;
use Hopr\Auth\Config;
use Hopr\Auth\Http\Request;
use Hopr\Auth\Http\Response;
use Hopr\Auth\Security\RateLimiter;
use PDO;

final class AdminController
{
    private const COOKIE_NAME = 'hopr_admin_session';
    private const SESSION_TTL_SECONDS = 28800; // 8 hours
    private const ALLOWED_STATUSES = ['active', 'trial', 'expired', 'suspended'];
    private const AVAILABLE_MODULES = ['whatsapp', 'invoices'];

    public function __construct(
        private readonly PDO $pdo,
        private readonly Config $config,
        private readonly RateLimiter $rateLimiter,
        private readonly ?DateTimeImmutable $fixedNow = null,
    ) {
    }

    public function handle(Request $request): Response
    {
        if (!$this->isConfigured()) {
            return $this->html(503, $this->renderLayout(
                'Admin Not Configured',
                '<div class="card" style="max-width:520px;margin:48px auto;">'
                . '<h1>Admin Panel Not Configured</h1>'
                . '<p class="muted">Set <code>ADMIN_USERNAME</code> and <code>ADMIN_PASSWORD_HASH</code> in your <code>.env</code> file outside public_html to enable <code>/admin</code>.</p>'
                . '</div>'
            ));
        }

        $method = $request->method;
        $path = rtrim($request->path, '/') ?: '/';

        if ($method === 'POST' && $path === '/admin/login') {
            return $this->login($request);
        }

        $session = $this->verifySessionCookie($request->cookies[self::COOKIE_NAME] ?? null);
        if ($session === null) {
            return $this->html(200, $this->renderLoginPage());
        }

        $csrfToken = $this->csrfToken($session['exp']);

        if ($method === 'GET' && $path === '/admin') {
            return $this->dashboard($request, $csrfToken);
        }

        if ($method === 'POST') {
            $submittedCsrf = is_string($request->body['_csrf'] ?? null) ? $request->body['_csrf'] : '';
            if (!hash_equals($csrfToken, $submittedCsrf)) {
                return $this->html(403, $this->renderLayout(
                    'Invalid CSRF Token',
                    '<div class="card" style="max-width:480px;margin:48px auto;">'
                    . '<h1>Session Expired or Invalid Request</h1>'
                    . '<p class="muted">Please go back, refresh, and try again.</p>'
                    . '<a class="btn" href="/admin">Back to Dashboard</a>'
                    . '</div>'
                ));
            }

            return match ($path) {
                '/admin/logout' => $this->logout(),
                '/admin/users/update' => $this->updateUser($request),
                '/admin/users/revoke-sessions' => $this->revokeUserSessions($request),
                default => Response::redirect('/admin'),
            };
        }

        return Response::redirect('/admin');
    }

    private function isConfigured(): bool
    {
        $username = (string) $this->config->get('admin.username', '');
        $hash = (string) $this->config->get('admin.password_hash', '');
        $plain = (string) $this->config->get('admin.password', '');

        return $username !== '' && ($hash !== '' || $plain !== '');
    }

    private function login(Request $request): Response
    {
        $now = $this->now();
        if (!$this->rateLimiter->attempt('admin_login:' . $request->clientIp, 10, 900, $now)) {
            return $this->html(429, $this->renderLoginPage('Too many login attempts. Please try again in 15 minutes.'));
        }

        $username = is_string($request->body['username'] ?? null) ? trim($request->body['username']) : '';
        $password = is_string($request->body['password'] ?? null) ? $request->body['password'] : '';

        $expectedUser = (string) $this->config->get('admin.username', '');
        $expectedHash = (string) $this->config->get('admin.password_hash', '');
        $expectedPlain = (string) $this->config->get('admin.password', '');

        $userOk = $expectedUser !== '' && hash_equals($expectedUser, $username);
        $passOk = false;
        if ($expectedHash !== '') {
            $passOk = password_verify($password, $expectedHash);
        } elseif ($expectedPlain !== '') {
            $passOk = hash_equals($expectedPlain, $password);
        }

        if (!$userOk || !$passOk) {
            return $this->html(401, $this->renderLoginPage('Invalid username or password.'));
        }

        $exp = $now->getTimestamp() + self::SESSION_TTL_SECONDS;
        $cookieValue = $this->signSessionCookie($expectedUser, $exp);

        return Response::redirect('/admin', [
            'Set-Cookie' => $this->buildCookieHeader($cookieValue, self::SESSION_TTL_SECONDS),
        ]);
    }

    private function logout(): Response
    {
        return Response::redirect('/admin', [
            'Set-Cookie' => $this->buildCookieHeader('', 0),
        ]);
    }

    private function dashboard(Request $request, string $csrfToken): Response
    {
        $search = is_string($request->query['q'] ?? null) ? trim($request->query['q']) : '';
        $flash = '';
        if (($request->query['saved'] ?? '') === '1') {
            $flash = 'User settings updated.';
        } elseif (($request->query['revoked'] ?? '') === '1') {
            $flash = 'All active sessions revoked for user.';
        }

        $stats = $this->fetchStats();
        $users = $this->fetchUsers($search);

        return $this->html(200, $this->renderDashboard($users, $stats, $search, $flash, $csrfToken));
    }

    private function updateUser(Request $request): Response
    {
        $userId = filter_var($request->body['user_id'] ?? null, FILTER_VALIDATE_INT);
        if ($userId === false || $userId <= 0) {
            return Response::redirect('/admin');
        }

        $status = is_string($request->body['subscription_status'] ?? null)
            ? trim($request->body['subscription_status'])
            : 'active';
        if (!in_array($status, self::ALLOWED_STATUSES, true)) {
            $status = 'active';
        }

        $expiresRaw = is_string($request->body['subscription_expires_at'] ?? null)
            ? trim($request->body['subscription_expires_at'])
            : '';
        $expiresAt = null;
        if ($expiresRaw !== '') {
            if (preg_match('/^\d{4}-\d{2}-\d{2}$/', $expiresRaw) === 1) {
                $expiresAt = $expiresRaw . ' 23:59:59';
            } elseif (preg_match('/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$/', $expiresRaw) === 1) {
                $normalized = str_replace('T', ' ', $expiresRaw);
                $expiresAt = strlen($normalized) === 16 ? $normalized . ':00' : $normalized;
            }
        }

        $maxRaw = is_string($request->body['max_accounts'] ?? null) || is_int($request->body['max_accounts'] ?? null)
            ? trim((string) $request->body['max_accounts'])
            : '';
        $maxAccounts = null;
        if ($maxRaw !== '') {
            $parsedMax = filter_var($maxRaw, FILTER_VALIDATE_INT);
            if ($parsedMax !== false && $parsedMax >= 0) {
                $maxAccounts = $parsedMax;
            }
        }

        $rawModules = $request->body['modules'] ?? [];
        $modules = [];
        if (is_array($rawModules)) {
            foreach ($rawModules as $m) {
                if (is_string($m)) {
                    $clean = strtolower(trim($m));
                    if ($clean !== '' && preg_match('/^[a-z0-9_-]{1,32}$/', $clean) === 1) {
                        $modules[] = $clean;
                    }
                }
            }
        }
        $modules = array_values(array_unique($modules));
        $modulesJson = json_encode($modules, JSON_UNESCAPED_SLASHES);

        $emailVerified = ($request->body['email_verified'] ?? '0') === '1' ? 1 : 0;

        $stmt = $this->pdo->prepare(
            'UPDATE users
             SET subscription_status = :status,
                 subscription_expires_at = :expires_at,
                 max_accounts = :max_accounts,
                 modules = :modules,
                 email_verified = :email_verified
             WHERE id = :id'
        );
        $stmt->execute([
            ':status' => $status,
            ':expires_at' => $expiresAt,
            ':max_accounts' => $maxAccounts,
            ':modules' => $modulesJson,
            ':email_verified' => $emailVerified,
            ':id' => $userId,
        ]);

        $q = is_string($request->body['q'] ?? null) ? trim($request->body['q']) : '';
        $redirect = '/admin?saved=1' . ($q !== '' ? '&q=' . rawurlencode($q) : '');
        return Response::redirect($redirect);
    }

    private function revokeUserSessions(Request $request): Response
    {
        $userId = filter_var($request->body['user_id'] ?? null, FILTER_VALIDATE_INT);
        if ($userId === false || $userId <= 0) {
            return Response::redirect('/admin');
        }

        $nowStr = $this->now()->format('Y-m-d H:i:s');
        $stmt = $this->pdo->prepare(
            'UPDATE user_sessions SET revoked_at = :revoked_at WHERE user_id = :user_id AND revoked_at IS NULL'
        );
        $stmt->execute([
            ':revoked_at' => $nowStr,
            ':user_id' => $userId,
        ]);

        $q = is_string($request->body['q'] ?? null) ? trim($request->body['q']) : '';
        $redirect = '/admin?revoked=1' . ($q !== '' ? '&q=' . rawurlencode($q) : '');
        return Response::redirect($redirect);
    }

    /**
     * @return array<string, int>
     */
    private function fetchStats(): array
    {
        $row = $this->pdo->query(
            'SELECT
                COUNT(*) AS total_users,
                SUM(CASE WHEN email_verified = 1 THEN 1 ELSE 0 END) AS verified_users,
                SUM(CASE WHEN subscription_status IN ("active", "trial") THEN 1 ELSE 0 END) AS active_users
             FROM users'
        )->fetch();

        $invCount = (int) $this->pdo->query('SELECT COUNT(*) FROM invoices')->fetchColumn();

        return [
            'total_users' => (int) ($row['total_users'] ?? 0),
            'verified_users' => (int) ($row['verified_users'] ?? 0),
            'active_users' => (int) ($row['active_users'] ?? 0),
            'total_invoices' => $invCount,
        ];
    }

    /**
     * @return array<int, array<string, mixed>>
     */
    private function fetchUsers(string $search): array
    {
        if ($search !== '') {
            $like = '%' . $search . '%';
            $stmt = $this->pdo->prepare(
                'SELECT u.id, u.name, u.email, u.phone, u.email_verified, u.subscription_status,
                        u.subscription_expires_at, u.max_accounts, u.modules, u.business_name, u.created_at,
                        (SELECT COUNT(*) FROM invoices i WHERE i.user_id = u.id) AS invoice_count
                 FROM users u
                 WHERE u.email LIKE :q1 OR u.name LIKE :q2 OR u.phone LIKE :q3
                 ORDER BY u.id DESC
                 LIMIT 200'
            );
            $stmt->execute([':q1' => $like, ':q2' => $like, ':q3' => $like]);
            return $stmt->fetchAll();
        }

        $stmt = $this->pdo->query(
            'SELECT u.id, u.name, u.email, u.phone, u.email_verified, u.subscription_status,
                    u.subscription_expires_at, u.max_accounts, u.modules, u.business_name, u.created_at,
                    (SELECT COUNT(*) FROM invoices i WHERE i.user_id = u.id) AS invoice_count
             FROM users u
             ORDER BY u.id DESC
             LIMIT 200'
        );
        return $stmt->fetchAll();
    }

    private function signSessionCookie(string $username, int $exp): string
    {
        $payload = base64_encode((string) json_encode(['u' => $username, 'exp' => $exp]));
        $sig = hash_hmac('sha256', $payload, (string) $this->config->get('app.pepper'));
        return $payload . '.' . $sig;
    }

    /**
     * @return array{u: string, exp: int}|null
     */
    private function verifySessionCookie(?string $cookie): ?array
    {
        if ($cookie === null || !str_contains($cookie, '.')) {
            return null;
        }

        [$payload, $sig] = explode('.', $cookie, 2);
        $expectedSig = hash_hmac('sha256', $payload, (string) $this->config->get('app.pepper'));
        if (!hash_equals($expectedSig, $sig)) {
            return null;
        }

        $decoded = json_decode((string) base64_decode($payload, true), true);
        if (!is_array($decoded) || !isset($decoded['u'], $decoded['exp'])) {
            return null;
        }

        $exp = (int) $decoded['exp'];
        if ($exp <= $this->now()->getTimestamp()) {
            return null;
        }

        $expectedUser = (string) $this->config->get('admin.username', '');
        if (!hash_equals($expectedUser, (string) $decoded['u'])) {
            return null;
        }

        return ['u' => (string) $decoded['u'], 'exp' => $exp];
    }

    private function csrfToken(int $sessionExp): string
    {
        return hash_hmac('sha256', 'admin_csrf:' . $sessionExp, (string) $this->config->get('app.pepper'));
    }

    private function buildCookieHeader(string $value, int $maxAge): string
    {
        $parts = [
            self::COOKIE_NAME . '=' . $value,
            'Path=/admin',
            'Max-Age=' . $maxAge,
            'HttpOnly',
            'SameSite=Strict',
        ];
        if ((string) $this->config->get('app.env', 'production') === 'production') {
            $parts[] = 'Secure';
        }
        return implode('; ', $parts);
    }

    private function html(int $status, string $body): Response
    {
        return Response::html($status, $body, [
            'Content-Security-Policy' => "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'",
        ]);
    }

    private function renderLoginPage(?string $error = null): string
    {
        $errHtml = $error !== null
            ? '<div class="alert alert-err">' . $this->e($error) . '</div>'
            : '';

        $content = <<<HTML
<div class="card" style="max-width:400px;margin:72px auto;">
  <h1 style="margin:0 0 6px;">Hopr Admin</h1>
  <p class="muted" style="margin:0 0 20px;">Sign in to manage users, subscriptions, and modules.</p>
  {$errHtml}
  <form method="POST" action="/admin/login">
    <label>Username
      <input type="text" name="username" required autocomplete="username" autofocus>
    </label>
    <label>Password
      <input type="password" name="password" required autocomplete="current-password">
    </label>
    <button type="submit" class="btn btn-primary" style="width:100%;margin-top:8px;">Sign In</button>
  </form>
</div>
HTML;

        return $this->renderLayout('Hopr Admin — Sign In', $content);
    }

    /**
     * @param array<int, array<string, mixed>> $users
     * @param array<string, int> $stats
     */
    private function renderDashboard(array $users, array $stats, string $search, string $flash, string $csrfToken): string
    {
        $flashHtml = $flash !== '' ? '<div class="alert alert-ok">' . $this->e($flash) . '</div>' : '';
        $eSearch = $this->e($search);
        $eCsrf = $this->e($csrfToken);

        $rowsHtml = '';
        foreach ($users as $u) {
            $uid = (int) $u['id'];
            $modules = AuthService::parseModules($u['modules'] ?? null);
            $expiresVal = '';
            if (is_string($u['subscription_expires_at']) && $u['subscription_expires_at'] !== '') {
                $expiresVal = substr($u['subscription_expires_at'], 0, 10);
            }
            $maxVal = $u['max_accounts'] !== null ? (string) (int) $u['max_accounts'] : '';
            $verifiedChecked = (int) $u['email_verified'] === 1 ? 'checked' : '';
            $biz = is_string($u['business_name']) && $u['business_name'] !== ''
                ? '<div class="muted" style="font-size:12px;">' . $this->e($u['business_name']) . '</div>'
                : '';

            $statusOptions = '';
            foreach (self::ALLOWED_STATUSES as $st) {
                $sel = $u['subscription_status'] === $st ? 'selected' : '';
                $statusOptions .= '<option value="' . $st . '" ' . $sel . '>' . ucfirst($st) . '</option>';
            }

            $moduleChecks = '';
            foreach (self::AVAILABLE_MODULES as $mod) {
                $chk = in_array($mod, $modules, true) ? 'checked' : '';
                $moduleChecks .= '<label class="chk"><input type="checkbox" name="modules[]" value="' . $mod . '" ' . $chk . '> ' . $mod . '</label>';
            }

            $rowsHtml .= '<tr>'
                . '<td><strong>#' . $uid . '</strong><div class="muted" style="font-size:12px;">' . $this->e((string) $u['created_at']) . '</div></td>'
                . '<td><strong>' . $this->e((string) $u['name']) . '</strong><div>' . $this->e((string) $u['email']) . '</div><div class="muted" style="font-size:12px;">' . $this->e((string) $u['phone']) . '</div>' . $biz . '</td>'
                . '<td><span class="badge">' . (int) $u['invoice_count'] . ' inv</span></td>'
                . '<td>'
                . '<form method="POST" action="/admin/users/update" class="inline-form">'
                . '<input type="hidden" name="_csrf" value="' . $eCsrf . '">'
                . '<input type="hidden" name="user_id" value="' . $uid . '">'
                . '<input type="hidden" name="q" value="' . $eSearch . '">'
                . '<div class="grid-fields">'
                . '<label>Status<select name="subscription_status">' . $statusOptions . '</select></label>'
                . '<label>Expires<input type="date" name="subscription_expires_at" value="' . $this->e($expiresVal) . '" title="Leave blank for lifetime"></label>'
                . '<label>Max Accts<input type="number" min="0" name="max_accounts" value="' . $this->e($maxVal) . '" placeholder="∞" style="width:76px;"></label>'
                . '</div>'
                . '<div class="mod-row">'
                . $moduleChecks
                . '<label class="chk"><input type="checkbox" name="email_verified" value="1" ' . $verifiedChecked . '> verified</label>'
                . '<button type="submit" class="btn btn-primary btn-sm">Save</button>'
                . '</div>'
                . '</form>'
                . '</td>'
                . '<td>'
                . '<form method="POST" action="/admin/users/revoke-sessions">'
                . '<input type="hidden" name="_csrf" value="' . $eCsrf . '">'
                . '<input type="hidden" name="user_id" value="' . $uid . '">'
                . '<input type="hidden" name="q" value="' . $eSearch . '">'
                . '<button type="submit" class="btn btn-danger btn-sm">Logout All</button>'
                . '</form>'
                . '</td>'
                . '</tr>';
        }

        if ($rowsHtml === '') {
            $rowsHtml = '<tr><td colspan="5" class="muted" style="text-align:center;padding:24px;">No users found.</td></tr>';
        }

        $content = <<<HTML
<div class="topbar">
  <div>
    <h1 style="margin:0;font-size:22px;">Hopr Auth Admin</h1>
    <span class="muted" style="font-size:13px;">Manage subscriptions, account limits, modules, and sessions</span>
  </div>
  <form method="POST" action="/admin/logout" style="margin:0;">
    <input type="hidden" name="_csrf" value="{$eCsrf}">
    <button type="submit" class="btn btn-sm">Sign Out</button>
  </form>
</div>

{$flashHtml}

<div class="stats">
  <div class="stat"><div class="stat-num">{$stats['total_users']}</div><div class="muted">Total Users</div></div>
  <div class="stat"><div class="stat-num">{$stats['verified_users']}</div><div class="muted">Verified</div></div>
  <div class="stat"><div class="stat-num">{$stats['active_users']}</div><div class="muted">Active / Trial</div></div>
  <div class="stat"><div class="stat-num">{$stats['total_invoices']}</div><div class="muted">Synced Invoices</div></div>
</div>

<div class="card">
  <form method="GET" action="/admin" class="search-bar">
    <input type="text" name="q" value="{$eSearch}" placeholder="Search by email, name, or phone...">
    <button type="submit" class="btn btn-primary btn-sm">Search</button>
    <a href="/admin" class="btn btn-sm">Reset</a>
  </form>

  <div style="overflow-x:auto;">
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>User</th>
          <th>Data</th>
          <th>Subscription, Limits &amp; Modules</th>
          <th>Sessions</th>
        </tr>
      </thead>
      <tbody>{$rowsHtml}</tbody>
    </table>
  </div>
</div>
HTML;

        return $this->renderLayout('Hopr Admin Dashboard', $content);
    }

    private function renderLayout(string $title, string $body): string
    {
        $eTitle = $this->e($title);
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{$eTitle}</title>
<style>
  * { box-sizing: border-box; }
  body { margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f172a; color: #e2e8f0; padding: 24px; }
  .wrap { max-width: 1180px; margin: 0 auto; }
  .topbar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  .card { background: #1e293b; border: 1px solid #334155; border-radius: 12px; padding: 20px; }
  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 18px; }
  .stat { background: #1e293b; border: 1px solid #334155; border-radius: 10px; padding: 14px 16px; }
  .stat-num { font-size: 26px; font-weight: 700; color: #f8fafc; }
  .muted { color: #94a3b8; }
  label { display: block; font-size: 12px; color: #94a3b8; margin-bottom: 10px; }
  input[type=text], input[type=password], input[type=date], input[type=number], select {
    width: 100%; padding: 8px 10px; border-radius: 6px; border: 1px solid #475569;
    background: #0f172a; color: #f8fafc; font-size: 13px; margin-top: 4px;
  }
  .btn { display: inline-block; padding: 8px 14px; border-radius: 6px; border: 1px solid #475569; background: #334155; color: #f8fafc; cursor: pointer; font-size: 13px; text-decoration: none; font-weight: 600; }
  .btn-primary { background: #2563eb; border-color: #2563eb; }
  .btn-danger { background: #dc2626; border-color: #dc2626; }
  .btn-sm { padding: 6px 10px; font-size: 12px; }
  .alert { padding: 10px 14px; border-radius: 8px; margin-bottom: 16px; font-size: 13px; }
  .alert-ok { background: #064e3b; border: 1px solid #10b981; color: #d1fae5; }
  .alert-err { background: #7f1d1d; border: 1px solid #ef4444; color: #fee2e2; }
  .search-bar { display: flex; gap: 8px; margin-bottom: 16px; }
  .search-bar input { margin-top: 0; max-width: 340px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 12px 10px; border-bottom: 1px solid #334155; vertical-align: top; }
  th { color: #94a3b8; font-weight: 600; font-size: 12px; text-transform: uppercase; }
  .grid-fields { display: flex; gap: 8px; flex-wrap: wrap; }
  .grid-fields label { margin-bottom: 6px; }
  .mod-row { display: flex; gap: 12px; align-items: center; flex-wrap: wrap; margin-top: 4px; }
  .chk { display: inline-flex; align-items: center; gap: 4px; margin: 0; color: #e2e8f0; font-size: 12px; cursor: pointer; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; background: #334155; font-size: 12px; }
  code { background: #0f172a; padding: 2px 6px; border-radius: 4px; }
</style>
</head>
<body>
<div class="wrap">{$body}</div>
</body>
</html>
HTML;
    }

    private function e(string $value): string
    {
        return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }

    private function now(): DateTimeImmutable
    {
        return $this->fixedNow ?? new DateTimeImmutable('now', new DateTimeZone('UTC'));
    }
}
