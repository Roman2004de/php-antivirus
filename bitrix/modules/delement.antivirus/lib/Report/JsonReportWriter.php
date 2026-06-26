<?php

namespace Delement\Antivirus\Report;

use RuntimeException;

class JsonReportWriter
{
    private const FILE_MODE = 0600;

    public function write(string $path, array $report): void
    {
        $json = json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('scan_report_encode_failed');
        }

        if (file_put_contents($path, $json, LOCK_EX) === false) {
            throw new RuntimeException('scan_report_save_failed');
        }

        @chmod($path, self::FILE_MODE);
    }

    public function read(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('scan_report_not_found');
        }

        $data = json_decode((string)file_get_contents($path), true);

        if (!is_array($data)) {
            throw new RuntimeException('scan_report_corrupted');
        }

        return $this->normalizeTagFields($data);
    }

    private function normalizeTagFields(array $report): array
    {
        if (isset($report['summary']) && is_array($report['summary']) && !isset($report['summary']['tags'])) {
            $report['summary']['tags'] = [];
        }

        if (!isset($report['results']) || !is_array($report['results'])) {
            return $report;
        }

        foreach ($report['results'] as &$result) {
            if (!is_array($result)) {
                continue;
            }

            if (!isset($result['tags']) || !is_array($result['tags'])) {
                $result['tags'] = [];
            }

            if (!array_key_exists('normalized_hash', $result)) {
                $result['normalized_hash'] = null;
            }

            if (!isset($result['findings']) || !is_array($result['findings'])) {
                continue;
            }

            foreach ($result['findings'] as &$finding) {
                if (!is_array($finding)) {
                    continue;
                }

                if (!isset($finding['tags']) || !is_array($finding['tags'])) {
                    $finding['tags'] = [];
                }

                if (!isset($finding['fingerprint'])) {
                    $finding['fingerprint'] = '';
                }
            }
            unset($finding);
        }
        unset($result);

        return $report;
    }
}
