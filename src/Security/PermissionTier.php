<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Security;

enum PermissionTier: string
{
    case READ = 'READ';
    case WRITE = 'WRITE';
    case EXECUTE = 'EXECUTE';
    case NETWORK = 'NETWORK';

    public function weight(): int
    {
        return match ($this) {
            self::READ => 1,
            self::WRITE => 2,
            self::EXECUTE => 3,
            self::NETWORK => 4,
        };
    }
}
