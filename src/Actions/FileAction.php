<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Actions;

use EidCloud\DesktopAgent\Audit\AuditLogger;
use EidCloud\DesktopAgent\Security\PermissionManager;
use EidCloud\DesktopAgent\Security\PermissionTier;
use EidCloud\DesktopAgent\Security\SecurityException;

class FileAction
{
    private string $backupDir;

    public function __construct(
        private readonly PermissionManager $permissionManager,
        private readonly AuditLogger $auditLogger,
        ?string $backupDir = null
    ) {
        $this->backupDir = $backupDir ?? ($permissionManager->getSandboxPath() . '/.agent_backups');
        if (!is_dir($this->backupDir)) {
            @mkdir($this->backupDir, 0755, true);
        }
    }

    public function readFile(string $path): string
    {
        $resolved = $this->permissionManager->validateFileAccess($path, PermissionTier::READ);

        if (!file_exists($resolved)) {
            $this->auditLogger->log(PermissionTier::READ, 'file_read_failed', $path, 'FAILURE', ['reason' => 'File not found']);
            throw new \RuntimeException("File not found: {$path}");
        }

        $content = file_get_contents($resolved);
        if ($content === false) {
            throw new \RuntimeException("Unable to read file: {$path}");
        }

        $this->auditLogger->log(PermissionTier::READ, 'file_read', $resolved, 'SUCCESS', [
            'bytes' => strlen($content),
            'md5' => md5($content),
        ]);

        return $content;
    }

    public function writeFile(string $path, string $content, bool $createBackup = true): bool
    {
        $resolved = $this->permissionManager->validateFileAccess($path, PermissionTier::WRITE);

        $oldContent = '';
        $backupPath = null;
        if (file_exists($resolved)) {
            $oldContent = (string) file_get_contents($resolved);
            if ($createBackup) {
                $backupPath = $this->backupFile($resolved);
            }
        }

        $dir = dirname($resolved);
        if (!is_dir($dir)) {
            mkdir($dir, 0755, true);
        }

        $diff = $this->generateDiff($oldContent, $content);
        $result = file_put_contents($resolved, $content);

        $this->auditLogger->log(
            PermissionTier::WRITE,
            file_exists($resolved) ? 'file_write' : 'file_create',
            $resolved,
            $result !== false ? 'SUCCESS' : 'FAILURE',
            [
                'bytes' => strlen($content),
                'backup' => $backupPath,
                'md5' => md5($content),
            ],
            $diff
        );

        return $result !== false;
    }

    public function listDirectory(string $dir = '.', bool $recursive = false): array
    {
        $resolved = $this->permissionManager->validateFileAccess($dir, PermissionTier::READ);

        if (!is_dir($resolved)) {
            throw new \RuntimeException("Directory not found: {$dir}");
        }

        $entries = [];
        if ($recursive) {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($resolved, \FilesystemIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::SELF_FIRST
            );
            foreach ($iterator as $item) {
                $entries[] = [
                    'path' => str_replace('\\', '/', $item->getPathname()),
                    'relative' => str_replace('\\', '/', substr($item->getPathname(), strlen($resolved) + 1)),
                    'type' => $item->isDir() ? 'dir' : 'file',
                    'size' => $item->isDir() ? 0 : $item->getSize(),
                    'modified' => date('c', $item->getMTime()),
                    'extension' => strtolower($item->getExtension()),
                ];
            }
        } else {
            $items = scandir($resolved);
            if ($items !== false) {
                foreach ($items as $item) {
                    if ($item === '.' || $item === '..') {
                        continue;
                    }
                    $fullPath = $resolved . '/' . $item;
                    $entries[] = [
                        'path' => $fullPath,
                        'name' => $item,
                        'type' => is_dir($fullPath) ? 'dir' : 'file',
                        'size' => is_dir($fullPath) ? 0 : filesize($fullPath),
                        'modified' => date('c', filemtime($fullPath)),
                        'extension' => pathinfo($item, PATHINFO_EXTENSION),
                    ];
                }
            }
        }

        $this->auditLogger->log(PermissionTier::READ, 'list_directory', $resolved, 'SUCCESS', [
            'count' => count($entries),
            'recursive' => $recursive,
        ]);

        return $entries;
    }

    public function moveFile(string $source, string $destination): bool
    {
        $resolvedSource = $this->permissionManager->validateFileAccess($source, PermissionTier::WRITE);
        $resolvedDest = $this->permissionManager->validateFileAccess($destination, PermissionTier::WRITE);

        if (!file_exists($resolvedSource)) {
            throw new \RuntimeException("Source file not found: {$source}");
        }

        $targetDir = dirname($resolvedDest);
        if (!is_dir($targetDir)) {
            mkdir($targetDir, 0755, true);
        }

        $this->backupFile($resolvedSource);
        $success = rename($resolvedSource, $resolvedDest);

        $this->auditLogger->log(
            PermissionTier::WRITE,
            'file_move',
            "{$resolvedSource} -> {$resolvedDest}",
            $success ? 'SUCCESS' : 'FAILURE'
        );

        return $success;
    }

    public function deleteFile(string $path): bool
    {
        $resolved = $this->permissionManager->validateFileAccess($path, PermissionTier::WRITE);

        if (!file_exists($resolved)) {
            return false;
        }

        $this->backupFile($resolved);
        $success = is_dir($resolved) ? rmdir($resolved) : unlink($resolved);

        $this->auditLogger->log(
            PermissionTier::WRITE,
            'file_delete',
            $resolved,
            $success ? 'SUCCESS' : 'FAILURE'
        );

        return $success;
    }

    private function backupFile(string $realPath): ?string
    {
        if (!file_exists($realPath) || is_dir($realPath)) {
            return null;
        }

        $backupFileName = basename($realPath) . '.' . date('Ymd_His') . '.' . bin2hex(random_bytes(3)) . '.bak';
        $backupPath = $this->backupDir . '/' . $backupFileName;

        @copy($realPath, $backupPath);
        return $backupPath;
    }

    private function generateDiff(string $old, string $new): string
    {
        if ($old === $new) {
            return "--- unchanged ---\n";
        }

        $oldLines = explode("\n", $old);
        $newLines = explode("\n", $new);
        $diff = "--- before\n+++ after\n";

        $max = max(count($oldLines), count($newLines));
        for ($i = 0; $i < $max; $i++) {
            $o = $oldLines[$i] ?? null;
            $n = $newLines[$i] ?? null;

            if ($o !== null && $n !== null) {
                if ($o !== $n) {
                    $diff .= "- {$o}\n+ {$n}\n";
                }
            } elseif ($o !== null) {
                $diff .= "- {$o}\n";
            } elseif ($n !== null) {
                $diff .= "+ {$n}\n";
            }
        }

        return $diff;
    }
}
