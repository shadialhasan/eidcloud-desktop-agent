<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent;

use EidCloud\DesktopAgent\Actions\FileAction;
use EidCloud\DesktopAgent\Actions\NetworkAction;
use EidCloud\DesktopAgent\Actions\ProcessAction;
use EidCloud\DesktopAgent\Audit\AuditLogger;
use EidCloud\DesktopAgent\Planner\TaskPlanner;
use EidCloud\DesktopAgent\Planner\TaskStep;
use EidCloud\DesktopAgent\Security\PermissionManager;
use EidCloud\DesktopAgent\Security\PermissionTier;
use EidCloud\DesktopAgent\Security\SecurityException;

class DesktopAgent
{
    private PermissionManager $permissionManager;
    private AuditLogger $auditLogger;
    private FileAction $fileAction;
    private ProcessAction $processAction;
    private NetworkAction $networkAction;
    private TaskPlanner $taskPlanner;

    public function __construct(
        string $sandboxPath,
        ?string $auditDir = null,
        ?string $sessionId = null
    ) {
        $this->permissionManager = new PermissionManager($sandboxPath);
        $resolvedAuditDir = $auditDir ?? ($this->permissionManager->getSandboxPath() . '/.audit');
        $this->auditLogger = new AuditLogger($resolvedAuditDir, $sessionId);

        $this->fileAction = new FileAction($this->permissionManager, $this->auditLogger);
        $this->processAction = new ProcessAction($this->permissionManager, $this->auditLogger);
        $this->networkAction = new NetworkAction($this->permissionManager, $this->auditLogger);
        $this->taskPlanner = new TaskPlanner();

        $this->auditLogger->log(
            PermissionTier::READ,
            'agent_initialized',
            $this->permissionManager->getSandboxPath(),
            'SUCCESS',
            ['session' => $this->auditLogger->getSessionId()]
        );
    }

    public function getPermissionManager(): PermissionManager
    {
        return $this->permissionManager;
    }

    public function getAuditLogger(): AuditLogger
    {
        return $this->auditLogger;
    }

    public function files(): FileAction
    {
        return $this->fileAction;
    }

    public function processes(): ProcessAction
    {
        return $this->processAction;
    }

    public function network(): NetworkAction
    {
        return $this->networkAction;
    }

    public function planner(): TaskPlanner
    {
        return $this->taskPlanner;
    }

    /**
     * Executes a natural language goal through atomic plan steps
     *
     * @param string $taskDescription
     * @return array{session_id: string, steps: list<array>, success: bool, message: string}
     */
    public function executeTask(string $taskDescription): array
    {
        $this->auditLogger->log(
            PermissionTier::READ,
            'task_received',
            $taskDescription,
            'SUCCESS'
        );

        $steps = $this->taskPlanner->plan($taskDescription, $this->permissionManager->getSandboxPath());
        $executedSteps = [];
        $overallSuccess = true;
        $errorMsg = null;

        foreach ($steps as $step) {
            try {
                // Verify tier permission
                if (!$this->permissionManager->hasPermission($step->requiredTier)) {
                    throw new SecurityException("Step {$step->stepNumber} requires tier [{$step->requiredTier->value}] which is not granted.");
                }

                $resultSummary = $this->dispatchStep($step);
                $step->status = 'SUCCESS';
                $step->result = $resultSummary;
            } catch (\Throwable $e) {
                $step->status = 'FAILED';
                $step->result = $e->getMessage();
                $overallSuccess = false;
                $errorMsg = "Step {$step->stepNumber} failed: " . $e->getMessage();
                $executedSteps[] = $step->toArray();
                break;
            }

            $executedSteps[] = $step->toArray();
        }

        $this->auditLogger->log(
            PermissionTier::READ,
            'task_completed',
            $taskDescription,
            $overallSuccess ? 'SUCCESS' : 'FAILED',
            ['executed_steps_count' => count($executedSteps)]
        );

        return [
            'session_id' => $this->auditLogger->getSessionId(),
            'steps' => $executedSteps,
            'success' => $overallSuccess,
            'message' => $overallSuccess ? 'Task completed successfully' : (string)$errorMsg,
        ];
    }

    private function dispatchStep(TaskStep $step): string
    {
        return match ($step->actionType) {
            'scan_and_index' => $this->executeScanAndIndex($step->parameters['path'] ?? '.'),
            'create_directories' => $this->executeCreateDirectories($step->parameters['base_path'] ?? '.'),
            'relocate_files' => $this->executeRelocateFiles($step->parameters['base_path'] ?? '.'),
            'compress_directory' => $this->executeCompressDirectory($step->parameters['base_path'] ?? '.'),
            'list_files' => $this->executeListFiles($step->parameters['path'] ?? '.'),
            'delete_files' => $this->executeDeleteFiles($step->parameters['path'] ?? '.'),
            'screen_metadata' => json_encode($this->processAction->getScreenBufferMetadata()),
            'execute_command' => $this->executeRunCommand($step->parameters['command'] ?? ''),
            default => 'Executed step: ' . $step->description,
        };
    }

    private function executeScanAndIndex(string $path): string
    {
        $items = $this->fileAction->listDirectory($path);
        $extensions = [];
        foreach ($items as $item) {
            if ($item['type'] === 'file') {
                $ext = $item['extension'] ?: 'no_ext';
                $extensions[$ext] = ($extensions[$ext] ?? 0) + 1;
            }
        }
        return 'Found ' . count($items) . ' items with extensions: ' . json_encode($extensions);
    }

    private function executeCreateDirectories(string $path): string
    {
        $items = $this->fileAction->listDirectory($path);
        $createdDirs = 0;
        foreach ($items as $item) {
            if ($item['type'] === 'file') {
                $ext = strtolower($item['extension'] ?: 'others');
                $targetDir = rtrim($this->permissionManager->getSandboxPath(), '/') . '/' . $ext;
                if (!is_dir($targetDir)) {
                    @mkdir($targetDir, 0755, true);
                    $createdDirs++;
                }
            }
        }
        return "Created {$createdDirs} category subdirectories";
    }

    private function executeRelocateFiles(string $path): string
    {
        $items = $this->fileAction->listDirectory($path);
        $moved = 0;
        $sandbox = rtrim($this->permissionManager->getSandboxPath(), '/');

        foreach ($items as $item) {
            if ($item['type'] === 'file') {
                $ext = strtolower($item['extension'] ?: 'others');
                $source = $item['path'];
                $destination = $sandbox . '/' . $ext . '/' . basename($source);
                if ($this->fileAction->moveFile($source, $destination)) {
                    $moved++;
                }
            }
        }
        return "Organized {$moved} files into categorized folders";
    }

    private function executeCompressDirectory(string $path): string
    {
        $sandbox = rtrim($this->permissionManager->getSandboxPath(), '/');
        $archiveFile = $sandbox . '/archive_' . date('Ymd_His') . '.zip';

        if (class_exists(\ZipArchive::class)) {
            $zip = new \ZipArchive();
            if ($zip->open($archiveFile, \ZipArchive::CREATE | \ZipArchive::OVERWRITE) === true) {
                $files = $this->fileAction->listDirectory($path, true);
                foreach ($files as $f) {
                    if ($f['type'] === 'file' && !str_ends_with($f['path'], '.zip')) {
                        $zip->addFile($f['path'], $f['relative']);
                    }
                }
                $zip->close();
                return "Created zip archive at: " . basename($archiveFile);
            }
        }

        // Fallback simulation/tar if ZipArchive not enabled
        file_put_contents($archiveFile . '.meta', 'Compressed archive of ' . $path);
        return "Created archive metadata at: " . basename($archiveFile);
    }

    private function executeListFiles(string $path): string
    {
        $items = $this->fileAction->listDirectory($path);
        return 'Listed ' . count($items) . ' items';
    }

    private function executeDeleteFiles(string $path): string
    {
        $items = $this->fileAction->listDirectory($path);
        $deleted = 0;
        foreach ($items as $item) {
            if ($item['type'] === 'file' && (str_ends_with($item['name'], '.tmp') || str_ends_with($item['name'], '.bak'))) {
                if ($this->fileAction->deleteFile($item['path'])) {
                    $deleted++;
                }
            }
        }
        return "Deleted {$deleted} temporary files";
    }

    private function executeRunCommand(string $command): string
    {
        $res = $this->processAction->executeCommand($command);
        return "Exit code: {$res['exit_code']}. Output: {$res['stdout']}";
    }
}
