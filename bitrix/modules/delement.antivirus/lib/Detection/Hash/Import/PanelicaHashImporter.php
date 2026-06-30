<?php

namespace Delement\Antivirus\Detection\Hash\Import;

class PanelicaHashImporter
{
    private const SOURCE_NAME = 'Panelica Malware Signatures';
    private const SOURCE_URL = 'https://github.com/Panelica/malware-signatures';

    private $moduleRoot;

    public function __construct(string $moduleRoot = null)
    {
        $this->moduleRoot = $moduleRoot !== null && $moduleRoot !== ''
            ? rtrim($moduleRoot, '/\\')
            : dirname(__DIR__, 4);
    }

    public function import(string $sourcePath, array $options = []): PanelicaImportResult
    {
        $warnings = [];
        $sourcePath = $this->normalizePath($sourcePath);
        $sourcePath = $sourcePath !== '' ? $this->resolvePath($sourcePath) : '';
        $sourceCommit = trim((string)($options['source_commit'] ?? ''));
        $metadata = SignatureSourceMetadata::panelica($sourceCommit);

        if ($sourcePath === '' || !is_dir($sourcePath)) {
            return PanelicaImportResult::error('panelica_source_not_found', $warnings);
        }

        $hashesJsonPath = $this->optionPath($options, 'hashes_json_path', $sourcePath . DIRECTORY_SEPARATOR . 'json' . DIRECTORY_SEPARATOR . 'hashes.json');
        $sha256TxtPath = $this->optionPath($options, 'sha256_txt_path', $sourcePath . DIRECTORY_SEPARATOR . 'hashes' . DIRECTORY_SEPARATOR . 'sha256.txt');
        $sourceUsed = '';
        $items = [];
        $normalizer = new PanelicaHashNormalizer();

        if ($hashesJsonPath !== '' && is_file($hashesJsonPath)) {
            $sourceUsed = 'json/hashes.json';
            $json = @file_get_contents($hashesJsonPath);

            if ($json === false || trim($json) === '') {
                return PanelicaImportResult::error('panelica_hashes_json_unreadable', $warnings);
            }

            $data = json_decode($json, true);

            if (!is_array($data)) {
                return PanelicaImportResult::error('panelica_hashes_json_invalid', $warnings);
            }

            $items = $normalizer->normalizeJsonData($data, $sourceUsed);
        } elseif ($sha256TxtPath !== '' && is_file($sha256TxtPath)) {
            $sourceUsed = 'hashes/sha256.txt';
            $content = @file_get_contents($sha256TxtPath);

            if ($content === false) {
                return PanelicaImportResult::error('panelica_sha256_txt_unreadable', $warnings);
            }

            $items = $normalizer->normalizeSha256Text($content, $sourceUsed);
        } else {
            return PanelicaImportResult::error('panelica_hash_source_not_found', $warnings);
        }

        if (empty($items)) {
            return PanelicaImportResult::error('panelica_no_valid_hashes', $warnings);
        }

        $prefixLength = $this->prefixLength($options['prefix_length'] ?? 8);
        $hashesOutput = $this->optionPath($options, 'hashes_output', $this->moduleRoot . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'signatures' . DIRECTORY_SEPARATOR . 'malware_hashes.json');
        $prefixesOutput = $this->optionPath($options, 'prefixes_output', $this->moduleRoot . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'signatures' . DIRECTORY_SEPARATOR . 'malware_hash_prefixes.json');
        $sourceDirectory = $this->moduleRoot . DIRECTORY_SEPARATOR . 'var' . DIRECTORY_SEPARATOR . 'signatures' . DIRECTORY_SEPARATOR . 'sources' . DIRECTORY_SEPARATOR . 'panelica';
        $prefixes = $this->buildPrefixes($items, $prefixLength);

        $this->writeJson($hashesOutput, [
            'version' => '1',
            'algorithm' => 'sha256',
            'source' => $metadata->toArray(),
            'items' => $items,
        ]);
        $this->writeJson($prefixesOutput, [
            'version' => '1',
            'algorithm' => 'sha256',
            'prefix_length' => $prefixLength,
            'source' => $metadata->toShortArray(),
            'prefixes' => $prefixes,
        ]);

        $licensePath = $this->optionPath($options, 'license_path', $sourcePath . DIRECTORY_SEPARATOR . 'LICENSE');
        $licenseCopied = $this->copyLicense($licensePath, $sourceDirectory, $warnings);
        $this->writeSourceReadme($sourceDirectory, $licenseCopied);

        $resultData = [
            'source_used' => $sourceUsed,
            'imported' => count($items),
            'skipped_invalid' => $normalizer->getSkippedInvalid(),
            'skipped_duplicates' => $normalizer->getSkippedDuplicates(),
            'prefixes_generated' => count($prefixes),
            'output' => [
                'hashes' => $hashesOutput,
                'prefixes' => $prefixesOutput,
                'source_directory' => $sourceDirectory,
            ],
            'warnings' => $warnings,
            'metadata' => $metadata->toArray(),
        ];
        $this->writeJson($sourceDirectory . DIRECTORY_SEPARATOR . 'import_metadata.json', $resultData);

        return PanelicaImportResult::success($resultData);
    }

    private function buildPrefixes(array $items, int $prefixLength): array
    {
        $prefixes = [];

        foreach ($items as $item) {
            $hash = (string)($item['hash'] ?? '');

            if ($hash !== '') {
                $prefixes[substr($hash, 0, $prefixLength)] = true;
            }
        }

        $result = array_keys($prefixes);
        sort($result, SORT_STRING);

        return $result;
    }

    private function copyLicense(string $licensePath, string $sourceDirectory, array &$warnings): bool
    {
        if ($licensePath === '' || !is_file($licensePath) || !is_readable($licensePath)) {
            $warnings[] = 'panelica_license_not_found';
            $this->ensureDirectory($sourceDirectory);

            return false;
        }

        $content = (string)file_get_contents($licensePath);

        if (stripos($content, 'MIT') === false && stripos($content, 'Permission is hereby granted') === false) {
            $warnings[] = 'panelica_license_mit_notice_not_detected';
        }

        $this->ensureDirectory($sourceDirectory);
        $target = $sourceDirectory . DIRECTORY_SEPARATOR . 'LICENSE';

        if (!@copy($licensePath, $target)) {
            $warnings[] = 'panelica_license_copy_failed';
            return false;
        }

        @chmod($target, 0600);

        return true;
    }

    private function writeSourceReadme(string $sourceDirectory, bool $licenseCopied): void
    {
        $this->ensureDirectory($sourceDirectory);
        $content = implode(PHP_EOL, [
            '# Panelica Malware Signatures',
            '',
            'This directory stores attribution metadata for hash signatures imported from Panelica Malware Signatures.',
            '',
            'Source: ' . self::SOURCE_URL,
            'License: MIT',
            'Imported data type: SHA-256 malware hashes only.',
            'Runtime scanner format: delement.antivirus internal JSON files.',
            'License copied: ' . ($licenseCopied ? 'yes' : 'no'),
            '',
        ]);
        $path = $sourceDirectory . DIRECTORY_SEPARATOR . 'README.source.md';

        file_put_contents($path, $content);
        @chmod($path, 0600);
    }

    private function writeJson(string $path, array $data): void
    {
        $this->ensureDirectory(dirname($path));
        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        if ($json === false) {
            throw new \RuntimeException('panelica_json_encode_failed');
        }

        if (@file_put_contents($path, $json . PHP_EOL) === false) {
            throw new \RuntimeException('panelica_output_write_failed');
        }

        @chmod($path, 0600);
    }

    private function ensureDirectory(string $path): void
    {
        if (is_dir($path)) {
            @chmod($path, 0700);
            return;
        }

        if (!@mkdir($path, 0700, true) && !is_dir($path)) {
            throw new \RuntimeException('panelica_output_directory_create_failed');
        }

        @chmod($path, 0700);
    }

    private function optionPath(array $options, string $name, string $default): string
    {
        $path = $this->normalizePath((string)($options[$name] ?? ''));

        return $path !== '' ? $this->resolvePath($path) : $this->resolvePath($default);
    }

    private function prefixLength($value): int
    {
        $value = (int)$value;

        if ($value < 8) {
            return 8;
        }

        if ($value > 12) {
            return 12;
        }

        return $value;
    }

    private function normalizePath(string $path): string
    {
        return trim($path);
    }

    private function resolvePath(string $path): string
    {
        if ($this->isAbsolutePath($path)) {
            return rtrim($path, '/\\');
        }

        $cwd = getcwd();
        $base = $cwd !== false && $cwd !== '' ? $cwd : $this->moduleRoot;

        return rtrim($base, '/\\') . DIRECTORY_SEPARATOR . $path;
    }

    private function isAbsolutePath(string $path): bool
    {
        return strpos($path, '/') === 0
            || strpos($path, '\\') === 0
            || preg_match('/^[a-zA-Z]:[\/\\\\]/', $path) === 1;
    }
}
