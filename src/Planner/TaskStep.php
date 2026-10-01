<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Planner;

use EidCloud\DesktopAgent\Security\PermissionTier;

class TaskStep
{
    public function __construct(
        public readonly int $stepNumber,
        public readonly string $description,
        public readonly PermissionTier $requiredTier,
        public readonly string $actionType,
        public readonly array $parameters = [],
        public string $status = 'PENDING',
        public ?string $result = null
    ) {
    }

    public function toArray(): array
    {
        return [
            'step' => $this->stepNumber,
            'description' => $this->description,
            'tier' => $this->requiredTier->value,
            'action_type' => $this->actionType,
            'parameters' => $this->parameters,
            'status' => $this->status,
            'result' => $this->result,
        ];
    }
}
