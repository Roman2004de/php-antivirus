<?php

namespace Delement\Antivirus\Cli;

use Delement\Antivirus\Detection\Hash\Import\PanelicaHashImporter;
use Delement\Antivirus\Detection\Hash\Import\PanelicaHashDownloader;
use RuntimeException;

class PanelicaImportCommand
{
    public const EXIT_OK = 0;
    public const EXIT_RUNTIME_ERROR = 3;

    private $moduleRoot;
    private $importer;
    private $downloader;

    public function __construct(string $moduleRoot, PanelicaHashImporter $importer = null, PanelicaHashDownloader $downloader = null)
    {
        $this->moduleRoot = rtrim($moduleRoot, '/\\');
        $this->importer = $importer ?: new PanelicaHashImporter($this->moduleRoot);
        $this->downloader = $downloader ?: new PanelicaHashDownloader($this->moduleRoot);
    }

    public function execute(array $cliOptions, bool $json = false, array $flags = []): array
    {
        try {
            $download = !empty($flags['download-panelica-hashes']);
            $sourcePath = (string)($cliOptions['import-panelica-hashes'] ?? $cliOptions['panelica-source'] ?? '');
            $downloadData = null;

            if ($download) {
                $downloadUrl = (string)($cliOptions['panelica-download-url'] ?? PanelicaHashDownloader::DEFAULT_SOURCE_URL);
                $downloadData = $this->downloader->download($downloadUrl);
                $sourcePath = (string)$downloadData['source_directory'];
            }

            if ($sourcePath === '') {
                return $this->error('panelica_source_required', $json);
            }

            $result = $this->importer->import($sourcePath, [
                'hashes_json_path' => (string)($cliOptions['panelica-hashes-json'] ?? ''),
                'sha256_txt_path' => (string)($cliOptions['panelica-sha256-txt'] ?? ''),
                'license_path' => (string)($cliOptions['panelica-license'] ?? ''),
                'hashes_output' => (string)($cliOptions['malware-hashes-output'] ?? ''),
                'prefixes_output' => (string)($cliOptions['malware-prefixes-output'] ?? ''),
                'prefix_length' => (int)($cliOptions['malware-hash-prefix-length'] ?? 8),
                'source_commit' => (string)($cliOptions['panelica-source-commit'] ?? ''),
            ]);

            if (!$result->isSuccess()) {
                return $this->error($result->getError(), $json, $result->toArray());
            }

            $payload = $result->toArray();

            if ($downloadData !== null) {
                $payload['download'] = $downloadData;
                $payload['warnings'] = array_values(array_unique(array_merge(
                    (array)($payload['warnings'] ?? []),
                    (array)($downloadData['warnings'] ?? [])
                )));
            }

            return [
                'exit_code' => self::EXIT_OK,
                'stdout' => $json ? $this->json($payload) . PHP_EOL : $this->humanSummary($payload),
                'stderr' => '',
            ];
        } catch (RuntimeException $exception) {
            return $this->error($exception->getMessage(), $json);
        } catch (\Throwable $exception) {
            return $this->error('internal_error', $json);
        }
    }

    private function humanSummary(array $payload): string
    {
        $lines = [
            'delement.antivirus Panelica hash import',
            'Status: ' . (string)($payload['status'] ?? 'unknown'),
            'Source used: ' . (string)($payload['source_used'] ?? ''),
            'Imported: ' . (int)($payload['imported'] ?? 0),
            'Skipped invalid: ' . (int)($payload['skipped_invalid'] ?? 0),
            'Skipped duplicates: ' . (int)($payload['skipped_duplicates'] ?? 0),
            'Prefixes generated: ' . (int)($payload['prefixes_generated'] ?? 0),
        ];

        if (!empty($payload['output']['hashes'])) {
            $lines[] = 'Hashes: ' . $payload['output']['hashes'];
        }

        if (!empty($payload['output']['prefixes'])) {
            $lines[] = 'Prefixes: ' . $payload['output']['prefixes'];
        }

        if (!empty($payload['warnings'])) {
            $lines[] = 'Warnings: ' . implode(', ', (array)$payload['warnings']);
        }

        return implode(PHP_EOL, $lines) . PHP_EOL;
    }

    private function error(string $error, bool $json, array $payload = []): array
    {
        $payload = array_merge([
            'status' => 'error',
            'source' => 'panelica',
            'error' => $error,
        ], $payload);

        return [
            'exit_code' => self::EXIT_RUNTIME_ERROR,
            'stdout' => $json ? $this->json($payload) . PHP_EOL : '',
            'stderr' => $json ? '' : $error . PHP_EOL,
        ];
    }

    private function json(array $payload): string
    {
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        return $json === false ? '{"status":"error","source":"panelica","error":"json_encode_failed"}' : $json;
    }
}
