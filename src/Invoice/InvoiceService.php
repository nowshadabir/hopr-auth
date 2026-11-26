<?php

declare(strict_types=1);

namespace Hopr\Auth\Invoice;

use DateTimeImmutable;
use DateTimeZone;
use Hopr\Auth\Auth\AuthService;
use Hopr\Auth\Http\Response;
use PDO;

final class InvoiceService
{
    public function __construct(
        private readonly PDO $pdo,
        private readonly AuthService $auth,
        private readonly ?DateTimeImmutable $fixedNow = null,
    ) {
    }

    /**
     * GET /invoices
     */
    public function list(?string $bearerToken): Response
    {
        $user = $this->authorizeInvoices($bearerToken);
        if ($user instanceof Response) {
            return $user;
        }

        $stmt = $this->pdo->prepare(
            'SELECT data_json
             FROM invoices
             WHERE user_id = :user_id
             ORDER BY updated_at_epoch DESC'
        );
        $stmt->execute([':user_id' => (int) $user['id']]);
        $rows = $stmt->fetchAll();

        $invoices = [];
        foreach ($rows as $row) {
            $decoded = json_decode((string) $row['data_json'], true);
            if (is_array($decoded)) {
                $invoices[] = $decoded;
            }
        }

        $businessName = $user['business_name'] ?? null;

        return Response::json(200, [
            'ok' => true,
            'business_name' => is_string($businessName) && $businessName !== '' ? $businessName : null,
            'invoices' => $invoices,
        ]);
    }

    /**
     * POST /invoices
     *
     * @param array<string, mixed> $body
     */
    public function upsert(?string $bearerToken, array $body): Response
    {
        $user = $this->authorizeInvoices($bearerToken);
        if ($user instanceof Response) {
            return $user;
        }

        $invoice = $body['invoice'] ?? null;
        if (!is_array($invoice)) {
            return Response::error(400, 'INVALID_INPUT', 'Invoice payload is required.');
        }

        $invoiceId = is_string($invoice['id'] ?? null) ? trim($invoice['id']) : '';
        $invoiceNo = is_string($invoice['invoice_no'] ?? null) ? trim($invoice['invoice_no']) : '';

        if ($invoiceId === '' || strlen($invoiceId) > 64 || preg_match('/[\x00-\x1F\x7F\/?#]/', $invoiceId) === 1) {
            return Response::error(400, 'INVALID_INPUT', 'Invalid invoice id (non-empty, max 64 chars).');
        }
        if ($invoiceNo === '' || strlen($invoiceNo) > 64) {
            return Response::error(400, 'INVALID_INPUT', 'Invalid invoice_no (non-empty, max 64 chars).');
        }

        // Security: never store logo images in the database
        unset($invoice['logo_data_url']);
        $invoice['id'] = $invoiceId;
        $invoice['invoice_no'] = $invoiceNo;

        $userId = (int) $user['id'];
        $now = $this->fixedNow ?? new DateTimeImmutable('now', new DateTimeZone('UTC'));
        $nowStr = $now->format('Y-m-d H:i:s');

        $rawEpoch = $invoice['updated_at_epoch'] ?? $now->getTimestamp();
        $updatedAtEpoch = is_numeric($rawEpoch) && (int) $rawEpoch > 0
            ? (int) $rawEpoch
            : $now->getTimestamp();

        $dataJson = json_encode($invoice, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($dataJson === false) {
            return Response::error(400, 'INVALID_INPUT', 'Failed to encode invoice JSON.');
        }

        $businessNameRaw = $body['business_name'] ?? null;
        $businessName = is_string($businessNameRaw)
            ? mb_substr(trim(preg_replace('/[\x00-\x1F\x7F]/u', '', $businessNameRaw) ?? ''), 0, 160, 'UTF-8')
            : '';

        $this->pdo->beginTransaction();
        try {
            // Verify ownership if invoice ID already exists
            $ownerStmt = $this->pdo->prepare('SELECT user_id FROM invoices WHERE id = :id LIMIT 1');
            $ownerStmt->execute([':id' => $invoiceId]);
            $existing = $ownerStmt->fetch();

            if ($existing !== false && (int) $existing['user_id'] !== $userId) {
                $this->pdo->rollBack();
                return Response::error(403, 'FORBIDDEN', 'You do not have permission to modify this invoice.');
            }

            $driver = (string) $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME);
            if ($driver === 'sqlite') {
                $sql = 'INSERT INTO invoices (id, user_id, invoice_no, data_json, updated_at_epoch, created_at, updated_at)
                        VALUES (:id, :user_id, :invoice_no, :data_json, :updated_at_epoch, :created_at, :updated_at)
                        ON CONFLICT(id) DO UPDATE SET
                            invoice_no = excluded.invoice_no,
                            data_json = excluded.data_json,
                            updated_at_epoch = excluded.updated_at_epoch,
                            updated_at = excluded.updated_at';
            } else {
                $sql = 'INSERT INTO invoices (id, user_id, invoice_no, data_json, updated_at_epoch, created_at, updated_at)
                        VALUES (:id, :user_id, :invoice_no, :data_json, :updated_at_epoch, :created_at, :updated_at)
                        ON DUPLICATE KEY UPDATE
                            invoice_no = VALUES(invoice_no),
                            data_json = VALUES(data_json),
                            updated_at_epoch = VALUES(updated_at_epoch),
                            updated_at = VALUES(updated_at)';
            }

            $upsert = $this->pdo->prepare($sql);
            $upsert->execute([
                ':id' => $invoiceId,
                ':user_id' => $userId,
                ':invoice_no' => $invoiceNo,
                ':data_json' => $dataJson,
                ':updated_at_epoch' => $updatedAtEpoch,
                ':created_at' => $nowStr,
                ':updated_at' => $nowStr,
            ]);

            if ($businessName !== '') {
                $updUser = $this->pdo->prepare('UPDATE users SET business_name = :business_name WHERE id = :id');
                $updUser->execute([
                    ':business_name' => $businessName,
                    ':id' => $userId,
                ]);
            }

            $this->pdo->commit();
        } catch (\Throwable $e) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $e;
        }

        return Response::json(200, [
            'ok' => true,
            'id' => $invoiceId,
        ]);
    }

    /**
     * DELETE /invoices/{id}
     */
    public function delete(?string $bearerToken, string $invoiceId): Response
    {
        $user = $this->authorizeInvoices($bearerToken);
        if ($user instanceof Response) {
            return $user;
        }

        $cleanId = trim($invoiceId);
        if ($cleanId === '' || strlen($cleanId) > 64) {
            return Response::error(400, 'INVALID_INPUT', 'Invalid invoice id.');
        }

        $stmt = $this->pdo->prepare(
            'DELETE FROM invoices WHERE id = :id AND user_id = :user_id'
        );
        $stmt->execute([
            ':id' => $cleanId,
            ':user_id' => (int) $user['id'],
        ]);

        return Response::json(200, [
            'ok' => true,
        ]);
    }

    /**
     * Authenticate token, check active subscription, and verify invoices module access.
     *
     * @return array<string, mixed>|Response
     */
    private function authorizeInvoices(?string $bearerToken): array|Response
    {
        $user = $this->auth->authenticate($bearerToken);
        if ($user instanceof Response) {
            return $user;
        }

        $modules = AuthService::parseModules($user['modules'] ?? null);
        $hasInvoices = in_array('invoices', $modules, true) || in_array('invoice', $modules, true);

        if (!$hasInvoices) {
            return Response::error(403, 'MODULE_LOCKED', 'Invoices module is not enabled for your account.');
        }

        return $user;
    }
}
