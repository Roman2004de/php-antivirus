<?php

namespace Delement\Antivirus\Detection\Hash\Import;

class PanelicaHashDownloader
{
    public const DEFAULT_SOURCE_URL = 'https://github.com/Panelica/malware-signatures';

    private const RELATIVE_FILES = [
        'LICENSE' => 1048576,
        'json/hashes.json' => 26214400,
        'hashes/sha256.txt' => 26214400,
    ];

    private $moduleRoot;
    private $timeoutSeconds;

    public function __construct(string $moduleRoot = null, int $timeoutSeconds = 20)
    {
        $this->moduleRoot = $moduleRoot !== null && $moduleRoot !== ''
            ? rtrim($moduleRoot, '/\\')
            : dirname(__DIR__, 4);
        $this->timeoutSeconds = max(3, min(120, $timeoutSeconds));
    }

    public function download(string $sourceUrl = self::DEFAULT_SOURCE_URL): array
    {
        $sourceUrl = trim($sourceUrl) !== '' ? trim($sourceUrl) : self::DEFAULT_SOURCE_URL;

        if (!$this->isAllowedSourceUrl($sourceUrl)) {
            throw new \RuntimeException('panelica_download_url_not_allowed');
        }

        $targetDirectory = $this->downloadDirectory();
        $warnings = [];
        $downloaded = [];

        foreach (self::RELATIVE_FILES as $relativePath => $maxBytes) {
            $content = $this->downloadRelativeFile($sourceUrl, $relativePath, $maxBytes);

            if ($content === null) {
                if ($relativePath === 'LICENSE') {
                    $warnings[] = 'panelica_license_download_failed';
                    continue;
                }

                if ($relativePath === 'json/hashes.json') {
                    $warnings[] = 'panelica_hashes_json_download_failed';
                    continue;
                }

                if ($relativePath === 'hashes/sha256.txt') {
                    $warnings[] = 'panelica_sha256_txt_download_failed';
                }

                continue;
            }

            $targetPath = $targetDirectory . DIRECTORY_SEPARATOR . str_replace('/', DIRECTORY_SEPARATOR, $relativePath);
            $this->writeFile($targetPath, $content);
            $downloaded[] = $relativePath;
        }

        if (
            !is_file($targetDirectory . DIRECTORY_SEPARATOR . 'json' . DIRECTORY_SEPARATOR . 'hashes.json')
            && !is_file($targetDirectory . DIRECTORY_SEPARATOR . 'hashes' . DIRECTORY_SEPARATOR . 'sha256.txt')
        ) {
            throw new \RuntimeException('panelica_download_hash_sources_not_found');
        }

        return [
            'source_url' => $sourceUrl,
            'source_directory' => $targetDirectory,
            'downloaded' => $downloaded,
            'warnings' => $warnings,
        ];
    }

    private function downloadRelativeFile(string $sourceUrl, string $relativePath, int $maxBytes): ?string
    {
        foreach ($this->candidateUrls($sourceUrl, $relativePath) as $candidateUrl) {
            $content = $this->fetch($candidateUrl, $maxBytes);

            if ($content !== null) {
                return $content;
            }
        }

        return null;
    }

    private function candidateUrls(string $sourceUrl, string $relativePath): array
    {
        if (strpos($sourceUrl, 'file://') === 0) {
            return [rtrim($sourceUrl, '/\\') . '/' . $relativePath];
        }

        $parts = parse_url($sourceUrl);
        $host = strtolower((string)($parts['host'] ?? ''));
        $path = trim((string)($parts['path'] ?? ''), '/');

        if ($host === 'raw.githubusercontent.com') {
            $segments = explode('/', $path);

            if (count($segments) >= 3) {
                return [rtrim($sourceUrl, '/') . '/' . $relativePath];
            }
        }

        if ($host === 'github.com') {
            $segments = explode('/', $path);

            if (count($segments) >= 4 && $segments[2] === 'tree') {
                $branch = $segments[3];

                return [
                    'https://raw.githubusercontent.com/Panelica/malware-signatures/' . rawurlencode($branch) . '/' . $relativePath,
                ];
            }

            return [
                'https://raw.githubusercontent.com/Panelica/malware-signatures/main/' . $relativePath,
                'https://raw.githubusercontent.com/Panelica/malware-signatures/master/' . $relativePath,
            ];
        }

        return [];
    }

    private function fetch(string $url, int $maxBytes): ?string
    {
        if (strpos($url, 'file://') === 0) {
            $path = substr($url, 7);
            $path = str_replace('/', DIRECTORY_SEPARATOR, $path);

            if (!is_file($path) || !is_readable($path)) {
                return null;
            }

            if (filesize($path) > $maxBytes) {
                return null;
            }

            $content = @file_get_contents($path);

            return $content === false ? null : $content;
        }

        if (function_exists('curl_init')) {
            $curl = curl_init($url);

            if ($curl === false) {
                return null;
            }

            $content = '';
            $tooLarge = false;
            curl_setopt_array($curl, [
                CURLOPT_RETURNTRANSFER => false,
                CURLOPT_HEADER => false,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_CONNECTTIMEOUT => $this->timeoutSeconds,
                CURLOPT_TIMEOUT => $this->timeoutSeconds,
                CURLOPT_SSL_VERIFYPEER => true,
                CURLOPT_SSL_VERIFYHOST => 2,
                CURLOPT_USERAGENT => 'delement.antivirus-panelica-importer',
                CURLOPT_WRITEFUNCTION => static function ($curlHandle, string $chunk) use (&$content, &$tooLarge, $maxBytes): int {
                    if (strlen($content) + strlen($chunk) > $maxBytes) {
                        $tooLarge = true;

                        return 0;
                    }

                    $content .= $chunk;

                    return strlen($chunk);
                },
            ]);

            $success = curl_exec($curl);
            $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
            curl_close($curl);

            if ($success !== true || $tooLarge || $status < 200 || $status >= 300) {
                return null;
            }

            return $content;
        }

        $context = stream_context_create([
            'http' => [
                'timeout' => $this->timeoutSeconds,
                'ignore_errors' => true,
                'header' => "User-Agent: delement.antivirus-panelica-importer\r\n",
            ],
            'ssl' => [
                'verify_peer' => true,
                'verify_peer_name' => true,
            ],
        ]);
        $content = @file_get_contents($url, false, $context, 0, $maxBytes + 1);

        if ($content === false || strlen($content) > $maxBytes) {
            return null;
        }

        if (!$this->isSuccessfulStreamResponse(isset($http_response_header) ? $http_response_header : [])) {
            return null;
        }

        return $content;
    }

    private function isSuccessfulStreamResponse(array $headers): bool
    {
        $statusCode = null;

        foreach ($headers as $header) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#i', (string)$header, $matches) === 1) {
                $statusCode = (int)$matches[1];
            }
        }

        return $statusCode !== null && $statusCode >= 200 && $statusCode < 300;
    }

    private function isAllowedSourceUrl(string $sourceUrl): bool
    {
        if (strpos($sourceUrl, 'file://') === 0) {
            return true;
        }

        $parts = parse_url($sourceUrl);

        if (!is_array($parts) || strtolower((string)($parts['scheme'] ?? '')) !== 'https') {
            return false;
        }

        $host = strtolower((string)($parts['host'] ?? ''));
        $path = '/' . trim((string)($parts['path'] ?? ''), '/');

        if ($host === 'github.com') {
            return $path === '/Panelica/malware-signatures'
                || strpos($path, '/Panelica/malware-signatures/') === 0;
        }

        if ($host === 'raw.githubusercontent.com') {
            return strpos($path, '/Panelica/malware-signatures/') === 0;
        }

        return false;
    }

    private function downloadDirectory(): string
    {
        $directory = $this->moduleRoot
            . DIRECTORY_SEPARATOR . 'var'
            . DIRECTORY_SEPARATOR . 'signatures'
            . DIRECTORY_SEPARATOR . 'sources'
            . DIRECTORY_SEPARATOR . 'panelica'
            . DIRECTORY_SEPARATOR . 'downloads'
            . DIRECTORY_SEPARATOR . gmdate('Ymd_His') . '_' . bin2hex(random_bytes(4));
        $this->ensureDirectory($directory);

        return $directory;
    }

    private function writeFile(string $path, string $content): void
    {
        $this->ensureDirectory(dirname($path));

        if (@file_put_contents($path, $content) === false) {
            throw new \RuntimeException('panelica_download_write_failed');
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
            throw new \RuntimeException('panelica_download_directory_create_failed');
        }

        @chmod($path, 0700);
    }
}
