<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Tests;

use EidCloud\DesktopAgent\DesktopAgent;
use EidCloud\DesktopAgent\Security\PermissionManager;
use EidCloud\DesktopAgent\Security\PermissionTier;
use EidCloud\DesktopAgent\Security\SecurityException;
use EidCloud\DesktopAgent\Audit\AuditLogger;

class DesktopAgentTest
{
    private string $testSandbox;

    public function __construct()
    {
        $this->testSandbox = sys_get_temp_dir() . '/eidcloud_test_' . bin2hex(random_bytes(4));
        if (!is_dir($this->testSandbox)) {
            mkdir($this->testSandbox, 0755, true);
        }
    }

    public function cleanup(): void
    {
        $this->deleteDir($this->testSandbox);
    }

    private function deleteDir(string $dir): void
    {
        if (!is_dir($dir)) {
            return;
        }
        $items = scandir($dir);
        if ($items === false) {
            return;
        }
        foreach ($items as $item) {
            if ($item === '.' || $item === '..') {
                continue;
            }
            $p = $dir . '/' . $item;
            if (is_dir($p)) {
                $this->deleteDir($p);
            } else {
                @unlink($p);
            }
        }
        @rmdir($dir);
    }

    public function testRbacEnforcement(): void
    {
        $pm = new PermissionManager($this->testSandbox);
        
        // READ is granted by default
        assert($pm->hasPermission(PermissionTier::READ) === true, 'READ should be granted by default');
        assert($pm->hasPermission(PermissionTier::WRITE) === false, 'WRITE should be denied by default');
        assert($pm->hasPermission(PermissionTier::EXECUTE) === false, 'EXECUTE should be denied by default');
        assert($pm->hasPermission(PermissionTier::NETWORK) === false, 'NETWORK should be denied by default');

        // Grant WRITE
        $pm->grant(PermissionTier::WRITE);
        assert($pm->hasPermission(PermissionTier::WRITE) === true, 'WRITE should now be granted');

        // Revoke WRITE
        $pm->revoke(PermissionTier::WRITE);
        assert($pm->hasPermission(PermissionTier::WRITE) === false, 'WRITE should now be revoked');
    }

    public function testSandboxPathContainment(): void
    {
        $pm = new PermissionManager($this->testSandbox);
        $pm->grant(PermissionTier::READ, PermissionTier::WRITE);

        // Within sandbox should succeed
        $validPath = $pm->validateFileAccess('test.txt', PermissionTier::WRITE);
        assert(str_starts_with(str_replace('\\', '/', $validPath), str_replace('\\', '/', $this->testSandbox)), 'Path must resolve inside sandbox');

        // Directory traversal escape must fail
        $caught = false;
        try {
            $pm->validateFileAccess('../../outside.txt', PermissionTier::WRITE);
        } catch (SecurityException $e) {
            $caught = true;
        }
        assert($caught === true, 'Directory traversal outside sandbox must throw SecurityException');
    }

    public function testFileOperationsWithDiffAndBackup(): void
    {
        $agent = new DesktopAgent($this->testSandbox);
        $agent->getPermissionManager()->grant(PermissionTier::READ, PermissionTier::WRITE);

        // Write file
        $ok = $agent->files()->writeFile('hello.txt', "Hello World\nLine 2");
        assert($ok === true, 'File write should succeed');

        // Read file
        $content = $agent->files()->readFile('hello.txt');
        assert(str_contains($content, 'Hello World'), 'File read content mismatch');

        // Overwrite file to trigger diff and automated backup
        $ok2 = $agent->files()->writeFile('hello.txt', "Hello World Modified\nLine 2");
        assert($ok2 === true, 'File update should succeed');

        // Verify audit log has diff
        $records = $agent->getAuditLogger()->getRecords();
        $writeRecords = array_filter($records, fn($r) => $r->action === 'file_write');
        $lastWrite = end($writeRecords);
        assert($lastWrite !== false && !empty($lastWrite->diff), 'Audit record must capture file diff');
    }

    public function testCommandExecutionAndWhitelist(): void
    {
        $agent = new DesktopAgent($this->testSandbox);
        $agent->getPermissionManager()->grant(PermissionTier::READ, PermissionTier::EXECUTE);

        // Allowed safe command (php -v)
        $res = $agent->processes()->executeCommand('php -v');
        assert($res['exit_code'] === 0, 'php -v should succeed');
        assert(str_contains($res['stdout'], 'PHP'), 'Stdout should contain PHP');

        // Blocked command not in whitelist
        $blocked = false;
        try {
            $agent->processes()->executeCommand('malicious_executable_xyz --run');
        } catch (SecurityException $e) {
            $blocked = true;
        }
        assert($blocked === true, 'Non-whitelisted command must be blocked');
    }

    public function testInteractiveModeRejection(): void
    {
        $pm = new PermissionManager($this->testSandbox);
        $pm->grant(PermissionTier::READ, PermissionTier::WRITE);
        
        // Register mock confirmation callback rejecting actions
        $pm->setInteractiveMode(true, function (string $action): bool {
            return false; // Reject
        });

        $rejected = false;
        try {
            $pm->validateFileAccess('secret.txt', PermissionTier::WRITE);
        } catch (SecurityException $e) {
            $rejected = true;
        }
        assert($rejected === true, 'Interactive mode rejection must abort operation');
    }

    public function testTaskPlannerAndExecution(): void
    {
        $workDir = $this->testSandbox . '/organize_test';
        mkdir($workDir, 0755, true);

        // Create sample files
        file_put_contents($workDir . '/doc1.txt', 'Document 1');
        file_put_contents($workDir . '/image1.png', 'PNG DATA');
        file_put_contents($workDir . '/data1.csv', 'a,b,c');

        $agent = new DesktopAgent($workDir);
        $agent->getPermissionManager()->grant(
            PermissionTier::READ,
            PermissionTier::WRITE,
            PermissionTier::EXECUTE
        );

        $result = $agent->executeTask("Organize files in {$workDir} by extension and archive");
        assert($result['success'] === true, 'Task execution should succeed: ' . $result['message']);
        assert(count($result['steps']) >= 3, 'Plan should contain multiple atomic steps');

        // Check if categorized subdirectories were created
        assert(is_dir($workDir . '/txt') || file_exists($workDir . '/txt/doc1.txt'), 'txt folder or moved file should exist');
    }

    public function testHighVelocityAuditTrail(): void
    {
        $agent = new DesktopAgent($this->testSandbox);
        $agent->getPermissionManager()->grant(PermissionTier::READ);

        $recordsCountBefore = count($agent->getAuditLogger()->getRecords());
        $agent->processes()->getScreenBufferMetadata();

        $records = $agent->getAuditLogger()->getRecords();
        assert(count($records) > $recordsCountBefore, 'Audit records count must increase');

        $last = end($records);
        assert($last->timestampNanoseconds > 0, 'Audit record must have nanosecond timestamp');
        assert(!empty($last->sessionId), 'Audit record must have session ID');

        // Check file storage
        $storedLogs = AuditLogger::readSessionLogs($this->testSandbox . '/.audit', $agent->getAuditLogger()->getSessionId());
        assert(!empty($storedLogs), 'Audit logs must persist to jsonl file');
    }
}
