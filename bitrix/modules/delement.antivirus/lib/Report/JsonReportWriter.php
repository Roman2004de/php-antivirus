<?php

namespace Delement\Antivirus\Report;

use RuntimeException;

class JsonReportWriter
{
    public function write(string $path, array $report): void
    {
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('Cannot encode scan report');
        }

        if (file_put_contents($path, $json, LOCK_EX) === false) {
            throw new RuntimeException('Cannot save scan report to ' . $path);
        }
    }

    public function read(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('Scan report not found');
        }

        $data = json_decode((string)file_get_contents($path), true);

        if (!is_array($data)) {
            throw new RuntimeException('Scan report is corrupted');
        }

        return $data;
    }
}
