<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Security;

class PermissionManager
{
    /** @var array<string, bool> */
    private array $grantedTiers = [];

    private string $sandboxPath;

    /** @var list<string> */
    private array $allowedCommandPrefixes = [];

    /** @var list<string> */
    private array $allowedDomains = [];

    private bool $interactiveMode = false;

    /** @var callable|null */
    private $confirmationCallback = null;

    public function __construct(string $sandboxPath)
    {
        $resolved = realpath($sandboxPath);
        if ($resolved === false) {
            if (!is_dir($sandboxPath)) {
                mkdir($sandboxPath, 0755, true);
            }
            $resolved = realpath($sandboxPath);
            if ($resolved === false) {
                $resolved = $sandboxPath;
            }
        }
        $this->sandboxPath = str_replace('\\', '/', $resolved);

        // Grant READ by default
        $this->grantedTiers[PermissionTier::READ->value] = true;

        // Default safe commands
        $this->allowedCommandPrefixes = [
            'php', 'git', 'dir', 'ls', 'echo', 'cat', 'type', 'find', 'tar', 'zip', 'unzip', 'compress-archive'
        ];
    }

    public function grant(PermissionTier ...$tiers): self
    {
        foreach ($tiers as $tier) {
            $this->grantedTiers[$tier->value] = true;
        }
        return $this;
    }

    public function revoke(PermissionTier ...$tiers): self
    {
        foreach ($tiers as $tier) {
            unset($this->grantedTiers[$tier->value]);
        }
        return $this;
    }

    public function hasPermission(PermissionTier $tier): bool
    {
        return isset($this->grantedTiers[$tier->value]);
    }

    public function setInteractiveMode(bool $interactive, ?callable $callback = null): self
    {
        $this->interactiveMode = $interactive;
        $this->confirmationCallback = $callback;
        return $this;
    }

    public function isInteractiveMode(): bool
    {
        return $this->interactiveMode;
    }

    public function setAllowedCommandPrefixes(array $prefixes): self
    {
        $this->allowedCommandPrefixes = array_values(array_map('strtolower', $prefixes));
        return $this;
    }

    public function addAllowedCommandPrefix(string $prefix): self
    {
        $this->allowedCommandPrefixes[] = strtolower($prefix);
        return $this;
    }

    public function getAllowedCommandPrefixes(): array
    {
        return $this->allowedCommandPrefixes;
    }

    public function setAllowedDomains(array $domains): self
    {
        $this->allowedDomains = array_values(array_map('strtolower', $domains));
        return $this;
    }

    public function addAllowedDomain(string $domain): self
    {
        $this->allowedDomains[] = strtolower($domain);
        return $this;
    }

    public function getAllowedDomains(): array
    {
        return $this->allowedDomains;
    }

    public function getSandboxPath(): string
    {
        return $this->sandboxPath;
    }

    public function validateFileAccess(string $path, PermissionTier $tier): string
    {
        if (!$this->hasPermission($tier)) {
            throw new SecurityException("Permission denied: Tier [{$tier->value}] is not granted.");
        }

        // Normalize path
        $cleanPath = str_replace('\\', '/', $path);
        
        // Canonical resolution
        $resolved = realpath($cleanPath);
        if ($resolved === false) {
            // If not directly resolvable from CWD, resolve relative to sandbox
            if (!preg_match('/^[a-zA-Z]:\//', $cleanPath) && !str_starts_with($cleanPath, '/')) {
                $cleanPath = $this->sandboxPath . '/' . preg_replace('#^(\./)+#', '', $cleanPath);
                $resolved = realpath($cleanPath);
            }
        }

        if ($resolved !== false) {
            $normalizedTarget = str_replace('\\', '/', $resolved);
        } else {
            // For files about to be created
            $dir = dirname($cleanPath);
            $realDir = realpath($dir);
            if ($realDir === false) {
                // If even the directory doesn't exist yet, simulate canonical path
                $normalizedTarget = $this->normalizePath($cleanPath);
            } else {
                $normalizedTarget = str_replace('\\', '/', $realDir) . '/' . basename($cleanPath);
            }
        }

        $normalizedSandbox = rtrim($this->sandboxPath, '/');

        // Check if path is within sandbox directory
        if ($normalizedTarget !== $normalizedSandbox && !str_starts_with($normalizedTarget, $normalizedSandbox . '/')) {
            throw new SecurityException("Sandbox violation: Path [{$path}] resolves to [{$normalizedTarget}], outside sandbox [{$normalizedSandbox}].");
        }

        if ($this->interactiveMode) {
            $this->requestConfirmation("File {$tier->value} on {$normalizedTarget}");
        }

        return $normalizedTarget;
    }

    public function validateCommandExecution(string $command): void
    {
        if (!$this->hasPermission(PermissionTier::EXECUTE)) {
            throw new SecurityException("Permission denied: Tier [EXECUTE] is not granted.");
        }

        $trimmed = trim($command);
        $parts = preg_split('/\s+/', $trimmed, 2);
        $executable = strtolower(basename($parts[0] ?? ''));
        $executableWithoutExt = preg_replace('/\.(exe|bat|cmd|sh)$/i', '', $executable);

        $allowed = false;
        foreach ($this->allowedCommandPrefixes as $prefix) {
            if ($executable === $prefix || $executableWithoutExt === $prefix) {
                $allowed = true;
                break;
            }
        }

        if (!$allowed) {
            throw new SecurityException("Command execution denied: Executable [{$executable}] is not in the whitelist.");
        }

        if ($this->interactiveMode) {
            $this->requestConfirmation("Execute shell command: {$command}");
        }
    }

    public function validateNetworkAccess(string $url): void
    {
        if (!$this->hasPermission(PermissionTier::NETWORK)) {
            throw new SecurityException("Permission denied: Tier [NETWORK] is not granted.");
        }

        $parts = parse_url($url);
        $host = strtolower($parts['host'] ?? '');

        if (empty($host)) {
            throw new SecurityException("Invalid network destination: [{$url}].");
        }

        if (!empty($this->allowedDomains)) {
            $allowed = false;
            foreach ($this->allowedDomains as $domain) {
                if ($host === $domain || str_ends_with($host, '.' . $domain)) {
                    $allowed = true;
                    break;
                }
            }

            if (!$allowed) {
                throw new SecurityException("Network access blocked: Host [{$host}] is not in approved domains list.");
            }
        }

        if ($this->interactiveMode) {
            $this->requestConfirmation("Network request to {$url}");
        }
    }

    private function requestConfirmation(string $action): void
    {
        if ($this->confirmationCallback !== null) {
            $approved = ($this->confirmationCallback)($action);
            if (!$approved) {
                throw new SecurityException("Operation cancelled by user: {$action}");
            }
            return;
        }

        // Terminal prompt
        echo "\n[SECURITY PROMPT] Authorize: {$action}? [y/N]: ";
        $handle = fopen('php://stdin', 'r');
        $line = trim((string) fgets($handle));
        if (strtolower($line) !== 'y') {
            throw new SecurityException("Operation cancelled by user: {$action}");
        }
    }

    private function normalizePath(string $path): string
    {
        $path = str_replace('\\', '/', $path);
        $parts = explode('/', $path);
        $safeParts = [];

        foreach ($parts as $part) {
            if ($part === '' || $part === '.') {
                continue;
            }
            if ($part === '..') {
                array_pop($safeParts);
            } else {
                $safeParts[] = $part;
            }
        }

        $prefix = '';
        if (preg_match('/^[a-zA-Z]:/', $path, $matches)) {
            $prefix = $matches[0];
            if (isset($safeParts[0]) && $safeParts[0] === $prefix) {
                array_shift($safeParts);
            }
            return $prefix . '/' . implode('/', $safeParts);
        }

        return (str_starts_with($path, '/') ? '/' : '') . implode('/', $safeParts);
    }
}
