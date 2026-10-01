<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\CLI;

use EidCloud\DesktopAgent\Audit\AuditLogger;
use EidCloud\DesktopAgent\DesktopAgent;
use EidCloud\DesktopAgent\Security\PermissionTier;

class ConsoleApp
{
    private string $version = '1.0.0';

    public function run(array $argv): int
    {
        array_shift($argv); // Remove script name

        $command = $argv[0] ?? '--help';
        if (str_starts_with($command, '-')) {
            $command = 'help';
        } else {
            array_shift($argv);
        }

        $options = $this->parseOptions($argv);

        if (isset($options['help']) || isset($options['h']) || $command === 'help') {
            $this->printHelp();
            return 0;
        }

        if (isset($options['version']) || isset($options['v']) || $command === 'version') {
            echo "eidcloud-desktop version {$this->version}\n";
            return 0;
        }

        return match ($command) {
            'run' => $this->handleRun($options),
            'audit-log' => $this->handleAuditLog($options),
            'plan' => $this->handlePlan($options),
            'status' => $this->handleStatus($options),
            default => $this->unknownCommand($command),
        };
    }

    private function parseOptions(array $args): array
    {
        $options = [];
        foreach ($args as $arg) {
            if (str_starts_with($arg, '--')) {
                $pos = strpos($arg, '=');
                if ($pos !== false) {
                    $key = substr($arg, 2, $pos - 2);
                    $val = substr($arg, $pos + 1);
                    $options[$key] = trim($val, '"\'');
                } else {
                    $options[substr($arg, 2)] = true;
                }
            } elseif (str_starts_with($arg, '-')) {
                $options[substr($arg, 1)] = true;
            }
        }
        return $options;
    }

    private function handleRun(array $options): int
    {
        $task = $options['task'] ?? null;
        $sandbox = $options['sandbox'] ?? './sandbox';
        $interactive = isset($options['interactive']);

        if (!$task) {
            echo "Error: Missing required option --task=\"...\"\n";
            echo "Run 'eidcloud-desktop --help' for usage.\n";
            return 1;
        }

        echo "🖥️  [eidcloud-desktop] Initializing Sandboxed OS Agent\n";
        echo "   Sandbox directory: {$sandbox}\n";
        echo "   Mode: " . ($interactive ? "Interactive Confirmation" : "Autonomous Headless") . "\n";
        echo "   Goal: \"{$task}\"\n\n";

        $agent = new DesktopAgent($sandbox);

        // Grant tiers required for agent execution
        $agent->getPermissionManager()->grant(
            PermissionTier::READ,
            PermissionTier::WRITE,
            PermissionTier::EXECUTE,
            PermissionTier::NETWORK
        );

        if ($interactive) {
            $agent->getPermissionManager()->setInteractiveMode(true);
        }

        echo "📋 [Task Plan Generated]:\n";
        $steps = $agent->planner()->plan($task, $agent->getPermissionManager()->getSandboxPath());
        foreach ($steps as $step) {
            echo "   [Step {$step->stepNumber}] [Tier: {$step->requiredTier->value}] {$step->description}\n";
        }
        echo "\n🚀 Executing Plan...\n";

        $result = $agent->executeTask($task);

        echo "\n📊 [Execution Results]:\n";
        foreach ($result['steps'] as $s) {
            $statusIcon = $s['status'] === 'SUCCESS' ? '✅' : '❌';
            echo "   {$statusIcon} Step {$s['step']}: {$s['description']}\n";
            echo "      Result: {$s['result']}\n";
        }

        echo "\nSession ID: {$result['session_id']}\n";
        echo "Audit Log: " . $agent->getAuditLogger()->getLogFilePath() . "\n";
        echo $result['success'] ? "✨ Task finished successfully!\n" : "⚠️ Task finished with errors: {$result['message']}\n";

        return $result['success'] ? 0 : 1;
    }

    private function handleAuditLog(array $options): int
    {
        $session = $options['session'] ?? 'latest';
        $sandbox = $options['sandbox'] ?? './sandbox';
        $auditDir = $options['audit-dir'] ?? ($sandbox . '/.audit');

        $logs = AuditLogger::readSessionLogs($auditDir, $session);

        if (empty($logs)) {
            echo "No audit log records found for session: '{$session}' in '{$auditDir}'.\n";
            return 0;
        }

        echo "📜 [Audit Trail - Session: {$session}] Total Events: " . count($logs) . "\n";
        echo str_repeat("─", 80) . "\n";

        foreach ($logs as $log) {
            $status = $log['status'] === 'SUCCESS' ? "\033[32mSUCCESS\033[0m" : "\033[31m{$log['status']}\033[0m";
            echo sprintf(
                "[%s] [%s] %-16s -> %s (%s)\n",
                $log['timestamp'],
                $log['tier'],
                $log['action'],
                $log['target'],
                $status
            );

            if (!empty($log['diff'])) {
                echo "      Diff:\n" . preg_replace('/^/m', '        ', $log['diff']) . "\n";
            }
        }
        echo str_repeat("─", 80) . "\n";
        return 0;
    }

    private function handlePlan(array $options): int
    {
        $task = $options['task'] ?? null;
        $sandbox = $options['sandbox'] ?? './sandbox';

        if (!$task) {
            echo "Error: Missing required option --task=\"...\"\n";
            return 1;
        }

        $agent = new DesktopAgent($sandbox);
        $steps = $agent->planner()->plan($task, $agent->getPermissionManager()->getSandboxPath());

        echo "📋 [Execution Plan for]: \"{$task}\"\n";
        echo "   Target Directory: {$sandbox}\n\n";

        foreach ($steps as $step) {
            echo "   [Step {$step->stepNumber}] [Tier: {$step->requiredTier->value}] {$step->description}\n";
            echo "      Action Type: {$step->actionType}\n";
        }

        return 0;
    }

    private function handleStatus(array $options): int
    {
        $sandbox = $options['sandbox'] ?? './sandbox';
        $agent = new DesktopAgent($sandbox);

        echo "🖥️  [eidcloud-desktop] Environment Status:\n";
        echo "   Sandbox: " . $agent->getPermissionManager()->getSandboxPath() . "\n";
        echo "   OS: " . PHP_OS . " (" . PHP_OS_FAMILY . ")\n";
        echo "   PHP: " . PHP_VERSION . "\n";
        echo "   Screen Buffer: " . json_encode($agent->processes()->getScreenBufferMetadata()) . "\n";

        return 0;
    }

    private function printHelp(): void
    {
        echo <<<HELP
🖥️  eidcloud-desktop - Sandboxed Local Computer & OS Control Agent (v{$this->version})

USAGE:
  php bin/eidcloud-desktop <command> [options]

COMMANDS:
  run          Execute a natural language desktop task inside a safe sandbox
  audit-log    Display the nanosecond audit trail for a session
  plan         Dry-run and inspect atomic steps for a natural language task
  status       Inspect sandbox and environment capabilities
  help         Display this help message

OPTIONS:
  --task="<goal>"        Natural language task or goal description (Required for run/plan)
  --sandbox="<path>"     Target isolated directory (Default: ./sandbox)
  --interactive          Prompt for user confirmation before executing WRITE/EXECUTE actions
  --session="<id>"       Session ID or 'latest' for audit logs (Default: latest)
  --audit-dir="<path>"   Directory containing audit logs
  --version, -v          Show version information
  --help, -h             Display command help

EXAMPLES:
  php bin/eidcloud-desktop run --task="Organize directory ./tmp by extension" --sandbox=./tmp
  php bin/eidcloud-desktop run --task="Organize downloads folder by filetype and compress archives" --sandbox=./workspace
  php bin/eidcloud-desktop plan --task="Clean temporary files in ./data" --sandbox=./data
  php bin/eidcloud-desktop audit-log --session=latest
  php bin/eidcloud-desktop status --sandbox=./tmp

RBAC PERMISSION TIERS:
  READ       Inspect filesystem, list processes, view screen buffer metadata.
  WRITE      Create/modify sandboxed workspace files with automated backups.
  EXECUTE    Run whitelisted shell commands with timeout guards and process isolation.
  NETWORK    Outbound HTTP requests to approved endpoints.

HELP;
    }

    private function unknownCommand(string $command): int
    {
        echo "Error: Unknown command '{$command}'.\n";
        echo "Run 'php bin/eidcloud-desktop --help' for available commands.\n";
        return 1;
    }
}
