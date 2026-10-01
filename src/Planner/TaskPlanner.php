<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Planner;

use EidCloud\DesktopAgent\Security\PermissionTier;

class TaskPlanner
{
    /**
     * Decomposes natural language instructions into atomic, verifiable TaskSteps
     *
     * @param string $taskDescription
     * @param string $contextPath
     * @return list<TaskStep>
     */
    public function plan(string $taskDescription, string $contextPath = '.'): array
    {
        $desc = strtolower(trim($taskDescription));
        $steps = [];
        $stepNum = 1;

        // Pattern 1: Organize / sort directory by extension or filetype
        if (str_contains($desc, 'organize') || str_contains($desc, 'sort') || str_contains($desc, 'categorize')) {
            $extracted = $this->extractPathFromDescription($taskDescription);
            $targetDir = ($extracted !== null && is_dir($extracted)) ? $extracted : $contextPath;

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Scan directory '{$targetDir}' and index files by extension",
                requiredTier: PermissionTier::READ,
                actionType: 'scan_and_index',
                parameters: ['path' => $targetDir]
            );

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Create category subdirectories in '{$targetDir}'",
                requiredTier: PermissionTier::WRITE,
                actionType: 'create_directories',
                parameters: ['base_path' => $targetDir]
            );

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Relocate files to matching subdirectories with atomic backups",
                requiredTier: PermissionTier::WRITE,
                actionType: 'relocate_files',
                parameters: ['base_path' => $targetDir]
            );

            if (str_contains($desc, 'compress') || str_contains($desc, 'zip') || str_contains($desc, 'archive')) {
                $steps[] = new TaskStep(
                    stepNumber: $stepNum++,
                    description: "Compress organized directories into archive",
                    requiredTier: PermissionTier::WRITE,
                    actionType: 'compress_directory',
                    parameters: ['base_path' => $targetDir]
                );
            }
        }
        // Pattern 2: Clean / prune / delete temp files
        elseif (str_contains($desc, 'clean') || str_contains($desc, 'delete') || str_contains($desc, 'remove') || str_contains($desc, 'prune')) {
            $targetDir = $this->extractPathFromDescription($taskDescription) ?? $contextPath;

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Locate matching files in '{$targetDir}' to clean",
                requiredTier: PermissionTier::READ,
                actionType: 'list_files',
                parameters: ['path' => $targetDir]
            );

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Safely remove matching files with backups",
                requiredTier: PermissionTier::WRITE,
                actionType: 'delete_files',
                parameters: ['path' => $targetDir]
            );
        }
        // Pattern 3: Backup files
        elseif (str_contains($desc, 'backup') || str_contains($desc, 'archive') || str_contains($desc, 'compress')) {
            $targetDir = $this->extractPathFromDescription($taskDescription) ?? $contextPath;

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Verify contents of target directory '{$targetDir}'",
                requiredTier: PermissionTier::READ,
                actionType: 'list_files',
                parameters: ['path' => $targetDir]
            );

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Create compressed zip archive in sandbox",
                requiredTier: PermissionTier::WRITE,
                actionType: 'compress_directory',
                parameters: ['base_path' => $targetDir]
            );
        }
        // Pattern 4: Execute / run command or script
        elseif (str_contains($desc, 'run') || str_contains($desc, 'execute') || str_contains($desc, 'script')) {
            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Verify environment and command permissions",
                requiredTier: PermissionTier::READ,
                actionType: 'screen_metadata',
                parameters: []
            );

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Execute task command: {$taskDescription}",
                requiredTier: PermissionTier::EXECUTE,
                actionType: 'execute_command',
                parameters: ['command' => $taskDescription]
            );
        }
        // Fallback generic inspection and execution
        else {
            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Inspect workspace environment: '{$contextPath}'",
                requiredTier: PermissionTier::READ,
                actionType: 'list_files',
                parameters: ['path' => $contextPath]
            );

            $steps[] = new TaskStep(
                stepNumber: $stepNum++,
                description: "Execute workflow step for: '{$taskDescription}'",
                requiredTier: PermissionTier::WRITE,
                actionType: 'custom_task',
                parameters: ['task' => $taskDescription, 'path' => $contextPath]
            );
        }

        return $steps;
    }

    private function extractPathFromDescription(string $description): ?string
    {
        if (preg_match('/(?:in|by|directory|folder|from)\s+([\'"]?)([^\s\'"]+)\1/i', $description, $matches)) {
            $path = trim($matches[2]);
            if (!empty($path) && $path !== 'extension' && $path !== 'filetype' && $path !== 'name' && $path !== 'size') {
                return $path;
            }
        }
        return null;
    }
}
