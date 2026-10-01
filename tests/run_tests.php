<?php

declare(strict_types=1);

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/DesktopAgentTest.php';

use EidCloud\DesktopAgent\Tests\DesktopAgentTest;

echo "🧪 Running EidCloud Desktop Agent Test Suite (PHP " . PHP_VERSION . ")...\n";
echo str_repeat("─", 70) . "\n";

$test = new DesktopAgentTest();
$methods = [
    'testRbacEnforcement',
    'testSandboxPathContainment',
    'testFileOperationsWithDiffAndBackup',
    'testCommandExecutionAndWhitelist',
    'testInteractiveModeRejection',
    'testTaskPlannerAndExecution',
    'testHighVelocityAuditTrail',
];

$passed = 0;
$failed = 0;

foreach ($methods as $method) {
    echo "  ▶ {$method}... ";
    $start = hrtime(true);
    try {
        $test->$method();
        $ms = round((hrtime(true) - $start) / 1e6, 2);
        echo "\033[32mPASSED\033[0m ({$ms}ms)\n";
        $passed++;
    } catch (\Throwable $e) {
        $ms = round((hrtime(true) - $start) / 1e6, 2);
        echo "\033[31mFAILED\033[0m ({$ms}ms)\n";
        echo "     Error: " . $e->getMessage() . "\n";
        echo "     File:  " . $e->getFile() . ":" . $e->getLine() . "\n";
        $failed++;
    }
}

$test->cleanup();

echo str_repeat("─", 70) . "\n";
if ($failed === 0) {
    echo "✨ All {$passed} tests passed successfully! (100% PASS)\n";
    exit(0);
} else {
    echo "❌ {$failed} test(s) failed, {$passed} passed.\n";
    exit(1);
}
