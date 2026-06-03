<?php

namespace Delement\Antivirus\Quarantine;

use RuntimeException;

class QuarantineManager
{
    public const STATUS_QUARANTINED = 'quarantined';
    public const STATUS_RESTORED = 'restored';
    public const STATUS_DELETED = 'deleted';

    private $rootPath;
    private $documentRoot;

    public function __construct(string $quarantinePath, string $documentRoot = '')
    {
        $this->documentRoot = rtrim($documentRoot, '/\\');
        $this->rootPath = $this->normalizeConfiguredPath($quarantinePath);
        $this->prepareDirectory($this->rootPath);
    }

    public function quarantine(string $filePath, array $scanResult, string $scanId): array
    {
        $sourcePath = realpath($filePath);

        if ($sourcePath === false || !is_file($sourcePath)) {
            throw new RuntimeException('quarantine_source_not_found');
        }

        if (!is_readable($sourcePath)) {
            throw new RuntimeException('quarantine_source_not_readable');
        }

        if ($this->isPathInside($sourcePath, $this->rootPath)) {
            throw new RuntimeException('quarantine_source_inside_quarantine');
        }

        $id = $this->createItemId();
        $itemPath = $this->rootPath . DIRECTORY_SEPARATOR . $id;
        $payloadPath = $itemPath . DIRECTORY_SEPARATOR . 'payload.bin';
        $metaPath = $itemPath . DIRECTORY_SEPARATOR . 'meta.json';

        $this->prepareDirectory($itemPath);

        $metadata = [
            'id' => $id,
            'status' => 'pending',
            'original_path' => $sourcePath,
            'original_name' => basename($sourcePath),
            'quarantine_path' => $payloadPath,
            'scan_id' => $scanId,
            'quarantined_at' => date('c'),
            'restored_at' => '',
            'deleted_at' => '',
            'file_hash' => isset($scanResult['file_hash']) ? (string)$scanResult['file_hash'] : $this->hashFile($sourcePath),
            'size' => filesize($sourcePath) ?: 0,
            'scan_status' => isset($scanResult['status']) ? (string)$scanResult['status'] : '',
            'score' => isset($scanResult['score']) ? (int)$scanResult['score'] : 0,
            'severity' => isset($scanResult['severity']) ? (string)$scanResult['severity'] : '',
            'findings' => isset($scanResult['findings']) && is_array($scanResult['findings']) ? $scanResult['findings'] : [],
        ];

        $this->writeMetadata($metaPath, $metadata);

        try {
            $this->moveFile($sourcePath, $payloadPath);
        } catch (RuntimeException $exception) {
            @unlink($metaPath);
            @rmdir($itemPath);
            throw $exception;
        }

        @chmod($payloadPath, 0600);

        $metadata['status'] = self::STATUS_QUARANTINED;
        $metadata['size'] = filesize($payloadPath) ?: $metadata['size'];
        $this->writeMetadata($metaPath, $metadata);

        return $metadata;
    }

    public function listItems(): array
    {
        if (!is_dir($this->rootPath)) {
            return [];
        }

        $files = glob($this->rootPath . DIRECTORY_SEPARATOR . '*' . DIRECTORY_SEPARATOR . 'meta.json');

        if (!is_array($files)) {
            return [];
        }

        usort($files, static function ($left, $right) {
            return filemtime($right) <=> filemtime($left);
        });

        $items = [];

        foreach ($files as $file) {
            try {
                $item = $this->readMetadata($file);
                $item['payload_exists'] = !empty($item['quarantine_path']) && is_file((string)$item['quarantine_path']);
                $items[] = $item;
            } catch (RuntimeException $exception) {
                continue;
            }
        }

        return $items;
    }

    public function restore(string $id): array
    {
        $item = $this->load($id);

        if ((string)($item['status'] ?? '') !== self::STATUS_QUARANTINED) {
            throw new RuntimeException('quarantine_item_not_active');
        }

        $payloadPath = isset($item['quarantine_path']) ? (string)$item['quarantine_path'] : '';
        $originalPath = isset($item['original_path']) ? (string)$item['original_path'] : '';

        if ($payloadPath === '' || !is_file($payloadPath)) {
            throw new RuntimeException('quarantine_payload_not_found');
        }

        if ($originalPath === '') {
            throw new RuntimeException('quarantine_original_path_empty');
        }

        if ($this->documentRoot !== '' && !$this->isPathInside($originalPath, $this->documentRoot)) {
            throw new RuntimeException('quarantine_restore_outside_document_root');
        }

        $targetDirectory = dirname($originalPath);

        if (!is_dir($targetDirectory) || !is_writable($targetDirectory)) {
            throw new RuntimeException('quarantine_restore_directory_not_writable');
        }

        if (is_file($originalPath) || is_dir($originalPath)) {
            throw new RuntimeException('quarantine_restore_target_exists');
        }

        $this->moveFile($payloadPath, $originalPath);

        $item['status'] = self::STATUS_RESTORED;
        $item['restored_at'] = date('c');
        $this->writeMetadata($this->getMetaPath($id), $item);

        return $item;
    }

    public function deletePayload(string $id): array
    {
        $item = $this->load($id);

        if ((string)($item['status'] ?? '') !== self::STATUS_QUARANTINED) {
            throw new RuntimeException('quarantine_item_not_active');
        }

        $payloadPath = isset($item['quarantine_path']) ? (string)$item['quarantine_path'] : '';

        if ($payloadPath !== '' && is_file($payloadPath) && !@unlink($payloadPath)) {
            throw new RuntimeException('quarantine_payload_delete_failed');
        }

        $item['status'] = self::STATUS_DELETED;
        $item['deleted_at'] = date('c');
        $this->writeMetadata($this->getMetaPath($id), $item);

        return $item;
    }

    public function load(string $id): array
    {
        return $this->readMetadata($this->getMetaPath($id));
    }

    private function normalizeConfiguredPath(string $path): string
    {
        $path = trim($path);

        if ($path === '') {
            throw new RuntimeException('quarantine_path_empty');
        }

        if ($this->documentRoot !== '') {
            $path = str_replace('#DOCUMENT_ROOT#', $this->documentRoot, $path);
        }

        if (strpos($path, "\0") !== false || preg_match('#(^|[\\\\/])\.\.([\\\\/]|$)#', $path)) {
            throw new RuntimeException('quarantine_path_invalid');
        }

        return rtrim($path, '/\\');
    }

    private function createItemId(): string
    {
        return date('Ymd_His') . '_' . bin2hex(random_bytes(8));
    }

    private function getMetaPath(string $id): string
    {
        $id = $this->sanitizeId($id);

        return $this->rootPath . DIRECTORY_SEPARATOR . $id . DIRECTORY_SEPARATOR . 'meta.json';
    }

    private function sanitizeId(string $id): string
    {
        if (!preg_match('/^[a-zA-Z0-9_.-]+$/', $id)) {
            throw new RuntimeException('quarantine_id_invalid');
        }

        return $id;
    }

    private function prepareDirectory(string $path): void
    {
        if (!is_dir($path) && !@mkdir($path, 0755, true) && !is_dir($path)) {
            throw new RuntimeException('quarantine_directory_create_failed');
        }

        if (!is_writable($path)) {
            throw new RuntimeException('quarantine_directory_not_writable');
        }

        $this->protectDirectory($path);
    }

    private function protectDirectory(string $path): void
    {
        $htaccess = rtrim($path, '/\\') . DIRECTORY_SEPARATOR . '.htaccess';
        $index = rtrim($path, '/\\') . DIRECTORY_SEPARATOR . 'index.php';

        if (!is_file($htaccess)) {
            @file_put_contents(
                $htaccess,
                "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n"
            );
        }

        if (!is_file($index)) {
            @file_put_contents($index, "<?php\nhttp_response_code(403);\n");
        }
    }

    private function readMetadata(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            throw new RuntimeException('quarantine_metadata_not_found');
        }

        $data = json_decode((string)file_get_contents($path), true);

        if (!is_array($data)) {
            throw new RuntimeException('quarantine_metadata_corrupted');
        }

        return $data;
    }

    private function writeMetadata(string $path, array $metadata): void
    {
        $json = json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('quarantine_metadata_encode_failed');
        }

        if (file_put_contents($path, $json, LOCK_EX) === false) {
            throw new RuntimeException('quarantine_metadata_save_failed');
        }

        @chmod($path, 0600);
    }

    private function moveFile(string $sourcePath, string $targetPath): void
    {
        if (@rename($sourcePath, $targetPath)) {
            return;
        }

        if (!@copy($sourcePath, $targetPath)) {
            throw new RuntimeException('quarantine_file_move_failed');
        }

        if (!@unlink($sourcePath)) {
            @unlink($targetPath);
            throw new RuntimeException('quarantine_source_delete_failed');
        }
    }

    private function hashFile(string $path): string
    {
        $hash = @hash_file('sha256', $path);

        return $hash === false ? '' : $hash;
    }

    private function isPathInside(string $path, string $basePath): bool
    {
        $normalizedPath = $this->normalizePath($path);
        $normalizedBase = $this->normalizePath($basePath);

        return $normalizedPath === $normalizedBase || strpos($normalizedPath, $normalizedBase . '/') === 0;
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower(rtrim($path, '/\\')));
    }
}
