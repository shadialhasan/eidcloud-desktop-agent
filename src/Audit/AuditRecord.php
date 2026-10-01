<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Audit;

class AuditRecord
{
    public function __construct(
        public readonly string $id,
        public readonly string $sessionId,
        public readonly string $timestampIso,
        public readonly int $timestampNanoseconds,
        public readonly string $tier,
        public readonly string $action,
        public readonly string $target,
        public readonly string $status,
        public readonly array $details = [],
        public readonly ?string $diff = null
    ) {
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'session_id' => $this->sessionId,
            'timestamp' => $this->timestampIso,
            'timestamp_ns' => $this->timestampNanoseconds,
            'tier' => $this->tier,
            'action' => $this->action,
            'target' => $this->target,
            'status' => $this->status,
            'details' => $this->details,
            'diff' => $this->diff,
        ];
    }
}
