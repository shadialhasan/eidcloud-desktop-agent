<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Audit;

use EidCloud\DesktopAgent\Security\PermissionTier;

class AuditLogger
{
    private string $sessionId;
    private string $storageDir;
    private string $logFilePath;

    /** @var list<AuditRecord> */
    private array $memoryRecords = [];

    public function __construct(string $storageDir, ?string $sessionId = null)
    {
        $this->storageDir = str_replace('\\', '/', $storageDir);
        if (!is_dir($this->storageDir)) {
            mkdir($this->storageDir, 0755, true);
        }

        $this->sessionId = $sessionId ?? bin2hex(random_bytes(8));
        $this->logFilePath = $this->storageDir . '/audit-' . $this->sessionId . '.jsonl';

        // Update latest pointer
        file_put_contents($this->storageDir . '/latest.session', $this->sessionId);
    }

    public function getSessionId(): string
    {
        return $this->sessionId;
    }

    public function getLogFilePath(): string
    {
        return $this->logFilePath;
    }

    public function log(
        PermissionTier|string $tier,
        string $action,
        string $target,
        string $status = 'SUCCESS',
        array $details = [],
        ?string $diff = null
    ): AuditRecord {
        $now = microtime(true);
        $seconds = (int)$now;
        $nanoseconds = (int)(hrtime(true));

        $record = new AuditRecord(
            id: bin2hex(random_bytes(6)),
            sessionId: $this->sessionId,
            timestampIso: date('Y-m-d\TH:i:s', $seconds) . '.' . sprintf('%06d', ($now - $seconds) * 1000000) . 'Z',
            timestampNanoseconds: $nanoseconds,
            tier: $tier instanceof PermissionTier ? $tier->value : $tier,
            action: $action,
            target: $target,
            status: $status,
            details: $details,
            diff: $diff
        );

        $this->memoryRecords[] = $record;

        $jsonLine = json_encode($record->toArray(), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
        file_put_contents($this->logFilePath, $jsonLine, FILE_APPEND | LOCK_EX);

        return $record;
    }

    /**
     * @return list<AuditRecord>
     */
    public function getRecords(): array
    {
        return $this->memoryRecords;
    }

    /**
     * Read records from a session ID or 'latest'
     * @return list<array>
     */
    public static function readSessionLogs(string $storageDir, string $sessionId = 'latest'): array
    {
        $storageDir = str_replace('\\', '/', $storageDir);
        if ($sessionId === 'latest') {
            $latestPointer = $storageDir . '/latest.session';
            if (!file_exists($latestPointer)) {
                return [];
            }
            $sessionId = trim((string) file_get_contents($latestPointer));
        }

        $logPath = $storageDir . '/audit-' . $sessionId . '.jsonl';
        if (!file_exists($logPath)) {
            return [];
        }

        $lines = file($logPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ($lines === false) {
            return [];
        }

        $records = [];
        foreach ($lines as $line) {
            $decoded = json_decode($line, true);
            if (is_array($decoded)) {
                $records[] = $decoded;
            }
        }

        return $records;
    }
}
