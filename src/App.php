<?php

declare(strict_types=1);

namespace Hopr\Auth;

use Hopr\Auth\Admin\AdminController;
use Hopr\Auth\Auth\AuthService;
use Hopr\Auth\Http\Request;
use Hopr\Auth\Http\Response;
use Hopr\Auth\Invoice\InvoiceService;

final class App
{
    public function __construct(
        private readonly AuthService $auth,
        private readonly InvoiceService $invoices,
        private readonly ?AdminController $admin = null,
    ) {
    }

    public function handle(Request $request): Response
    {
        $method = $request->method;
        $path = rtrim($request->path, '/') ?: '/';

        if ($method === 'OPTIONS') {
            return new Response(204, []);
        }

        if ($this->admin !== null && ($path === '/admin' || str_starts_with($path, '/admin/'))) {
            return $this->admin->handle($request);
        }

        if ($method === 'DELETE' && preg_match('#^/invoices/([^/]+)$#', $path, $matches) === 1) {
            return $this->invoices->delete($request->getBearerToken(), urldecode($matches[1]));
        }

        return match ([$method, $path]) {
            ['POST', '/auth/signup'] => $this->auth->signup($request->body, $request->clientIp),
            ['POST', '/auth/verify-otp'] => $this->auth->verifyOtp($request->body, $request->clientIp),
            ['POST', '/auth/resend-otp'] => $this->auth->resendOtp($request->body, $request->clientIp),
            ['POST', '/auth/login'] => $this->auth->login($request->body, $request->clientIp),
            ['GET', '/auth/me'] => $this->auth->me($request->getBearerToken()),
            ['POST', '/auth/logout'] => $this->auth->logout($request->getBearerToken()),
            ['GET', '/invoices'] => $this->invoices->list($request->getBearerToken()),
            ['POST', '/invoices'] => $this->invoices->upsert($request->getBearerToken(), $request->body),
            default => Response::error(404, 'NOT_FOUND', 'Endpoint not found.'),
        };
    }
}
