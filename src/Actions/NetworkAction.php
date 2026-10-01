<?php

declare(strict_types=1);

namespace EidCloud\DesktopAgent\Actions;

use EidCloud\DesktopAgent\Audit\AuditLogger;
use EidCloud\DesktopAgent\Security\PermissionManager;
use EidCloud\DesktopAgent\Security\PermissionTier;

class NetworkAction
{
    public function __construct(
        private readonly PermissionManager $permissionManager,
        private readonly AuditLogger $auditLogger
    ) {
    }

    public function request(string $method, string $url, array $headers = [], ?string $body = null, int $timeoutSeconds = 15): array
    {
        $this->permissionManager->validateNetworkAccess($url);

        $startTime = hrtime(true);

        $curl = curl_init();
        $formattedHeaders = [];
        foreach ($headers as $k => $v) {
            $formattedHeaders[] = "{$k}: {$v}";
        }

        curl_setopt_array($curl, [
            CURLOPT_URL => $url,
            CURLOPT_CUSTOMREQUEST => strtoupper($method),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $formattedHeaders,
            CURLOPT_TIMEOUT => $timeoutSeconds,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_USERAGENT => 'EidCloud-Desktop-Agent/1.0',
        ]);

        if ($body !== null && in_array(strtoupper($method), ['POST', 'PUT', 'PATCH'], true)) {
            curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
        }

        $responseBody = curl_exec($curl);
        $error = curl_error($curl);
        $httpCode = (int)curl_getinfo($curl, CURLINFO_HTTP_CODE);
        curl_close($curl);

        $durationMs = (hrtime(true) - $startTime) / 1e6;

        $result = [
            'status_code' => $httpCode,
            'body' => $responseBody !== false ? (string)$responseBody : null,
            'error' => $error ?: null,
            'duration_ms' => round($durationMs, 2),
        ];

        $this->auditLogger->log(
            PermissionTier::NETWORK,
            'http_request',
            "{$method} {$url}",
            ($httpCode >= 200 && $httpCode < 400) ? 'SUCCESS' : 'FAILURE',
            [
                'http_code' => $httpCode,
                'duration_ms' => round($durationMs, 2),
                'bytes' => is_string($responseBody) ? strlen($responseBody) : 0,
            ]
        );

        return $result;
    }
}
