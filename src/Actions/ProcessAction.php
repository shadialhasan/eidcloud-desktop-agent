<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Actions;

use EidCloud\DesktopAgent\Audit\AuditLogger;
use EidCloud\DesktopAgent\Security\PermissionManager;
use EidCloud\DesktopAgent\Security\PermissionTier;
use EidCloud\DesktopAgent\Security\SecurityException;

class ProcessAction
{
    public function __construct(
        private readonly PermissionManager $permissionManager,
        private readonly AuditLogger $auditLogger
    ) {
    }

    public function listProcesses(int $limit = 50): array
    {
        if (!$this->permissionManager->hasPermission(PermissionTier::READ)) {
            throw new SecurityException("Permission READ required to view processes.");
        }

        $processes = [];
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';

        if ($isWindows) {
            $output = @shell_exec('tasklist /FO CSV /NH');
            if ($output) {
                $lines = explode("\n", trim($output));
                foreach ($lines as $line) {
                    $row = str_getcsv($line);
                    if (isset($row[0], $row[1])) {
                        $processes[] = [
                            'name' => $row[0],
                            'pid' => (int)$row[1],
                            'session_name' => $row[2] ?? '',
                            'mem_usage' => $row[4] ?? '',
                        ];
                    }
                }
            }
        } else {
            $output = @shell_exec('ps aux --no-heading 2>/dev/null || ps -ef');
            if ($output) {
                $lines = explode("\n", trim($output));
                foreach ($lines as $line) {
                    $parts = preg_split('/\s+/', trim($line), 11);
                    if (count($parts) >= 2) {
                        $processes[] = [
                            'user' => $parts[0],
                            'pid' => (int)$parts[1],
                            'cpu' => $parts[2] ?? '0.0',
                            'mem' => $parts[3] ?? '0.0',
                            'command' => $parts[10] ?? ($parts[7] ?? 'unknown'),
                        ];
                    }
                }
            }
        }

        if (count($processes) > $limit) {
            $processes = array_slice($processes, 0, $limit);
        }

        $this->auditLogger->log(PermissionTier::READ, 'list_processes', 'OS_SYSTEM', 'SUCCESS', [
            'count' => count($processes),
            'platform' => PHP_OS_FAMILY,
        ]);

        return $processes;
    }

    public function getScreenBufferMetadata(): array
    {
        if (!$this->permissionManager->hasPermission(PermissionTier::READ)) {
            throw new SecurityException("Permission READ required to view screen buffer metadata.");
        }

        // Gather display / virtual console buffer info
        $metadata = [
            'os' => PHP_OS,
            'os_family' => PHP_OS_FAMILY,
            'screen_info' => 'Virtual Display Buffer / Headless Console',
            'terminal_cols' => (int)($_ENV['COLUMNS'] ?? 80),
            'terminal_lines' => (int)($_ENV['LINES'] ?? 24),
            'captured_at' => date('c'),
        ];

        $this->auditLogger->log(PermissionTier::READ, 'screen_buffer_metadata', 'DISPLAY_DEVICE', 'SUCCESS', $metadata);

        return $metadata;
    }

    public function executeCommand(string $command, int $timeoutSeconds = 30): array
    {
        $this->permissionManager->validateCommandExecution($command);

        $sandboxCwd = $this->permissionManager->getSandboxPath();
        $startTime = hrtime(true);

        $descriptors = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($command, $descriptors, $pipes, $sandboxCwd);

        if (!is_resource($process)) {
            $this->auditLogger->log(PermissionTier::EXECUTE, 'command_execution_failed', $command, 'FAILURE');
            throw new \RuntimeException("Failed to spawn process for command: {$command}");
        }

        fclose($pipes[0]);

        // Non-blocking read with timeout guard
        stream_set_blocking($pipes[1], false);
        stream_set_blocking($pipes[2], false);

        $stdout = '';
        $stderr = '';
        $start = microtime(true);
        $timedOut = false;

        while (true) {
            $stdout .= stream_get_contents($pipes[1]);
            $stderr .= stream_get_contents($pipes[2]);

            $status = proc_get_status($process);
            if (!$status['running']) {
                break;
            }

            if ((microtime(true) - $start) > $timeoutSeconds) {
                $timedOut = true;
                proc_terminate($process, 9);
                break;
            }

            usleep(10000); // 10ms
        }

        $stdout .= stream_get_contents($pipes[1]);
        $stderr .= stream_get_contents($pipes[2]);

        fclose($pipes[1]);
        fclose($pipes[2]);

        $exitCode = $timedOut ? -1 : proc_close($process);
        $durationMs = (hrtime(true) - $startTime) / 1e6;

        $result = [
            'command' => $command,
            'exit_code' => $exitCode,
            'stdout' => trim($stdout),
            'stderr' => trim($stderr),
            'timed_out' => $timedOut,
            'duration_ms' => round($durationMs, 2),
        ];

        $this->auditLogger->log(
            PermissionTier::EXECUTE,
            'command_execute',
            $command,
            $exitCode === 0 ? 'SUCCESS' : 'FAILURE',
            $result
        );

        return $result;
    }
}
