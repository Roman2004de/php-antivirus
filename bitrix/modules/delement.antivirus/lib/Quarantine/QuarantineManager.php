<?php

namespace Delement\Antivirus\Quarantine;

use RuntimeException;

class QuarantineManager
{
    public const STATUS_QUARANTINED = 'quarantined';
    public const STATUS_RESTORED = 'restored';
    public const STATUS_DELETED = 'deleted';

    private const DIRECTORY_MODE = 0700;
    private const FILE_MODE = 0600;

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
        $sourceHash = $this->hashFile($sourcePath);

        $this->prepareDirectory($itemPath);

        $metadata = [
            'id' => $id,
            'status' => 'pending',
            'original_path' => $sourcePath,
            'original_name' => basename($sourcePath),
            'quarantine_path' => $payloadPath,
            'critical_restore' => $this->isCriticalRestorePath($sourcePath),
            'scan_id' => $scanId,
            'quarantined_at' => date('c'),
            'restored_at' => '',
            'deleted_at' => '',
            'file_hash' => isset($scanResult['file_hash']) && (string)$scanResult['file_hash'] !== '' ? (string)$scanResult['file_hash'] : $sourceHash,
            'source_hash_before' => $sourceHash,
            'payload_hash_after' => '',
            'checksum_verified' => false,
            'size' => filesize($sourcePath) ?: 0,
            'scan_status' => isset($scanResult['status']) ? (string)$scanResult['status'] : '',
            'score' => isset($scanResult['score']) ? (int)$scanResult['score'] : 0,
            'severity' => isset($scanResult['severity']) ? (string)$scanResult['severity'] : '',
            'findings' => isset($scanResult['findings']) && is_array($scanResult['findings']) ? $scanResult['findings'] : [],
            'planned_action' => isset($scanResult['planned_action']) ? (string)$scanResult['planned_action'] : '',
            'action' => isset($scanResult['action']) ? (string)$scanResult['action'] : '',
            'action_status' => isset($scanResult['action_status']) ? (string)$scanResult['action_status'] : '',
        ];

        $this->writeMetadata($metaPath, $metadata);

        try {
            $move = $this->moveFile($sourcePath, $payloadPath, $sourceHash);
        } catch (RuntimeException $exception) {
            @unlink($metaPath);
            @rmdir($itemPath);
            throw $exception;
        }

        @chmod($payloadPath, self::FILE_MODE);

        $metadata['status'] = self::STATUS_QUARANTINED;
        $metadata['size'] = filesize($payloadPath) ?: $metadata['size'];
        $metadata['payload_hash_after'] = (string)$move['target_hash'];
        $metadata['checksum_verified'] = $this->hashesMatch((string)$move['source_hash'], (string)$move['target_hash']);
        $this->writeMetadata($metaPath, $metadata);

        return $metadata;
    }

    public function deleteOriginal(string $filePath, array $scanResult, string $scanId): array
    {
        $sourcePath = realpath($filePath);

        if ($sourcePath === false || !is_file($sourcePath)) {
            throw new RuntimeException('delete_source_not_found');
        }

        if ($this->documentRoot !== '' && !$this->isPathInside($sourcePath, $this->documentRoot)) {
            throw new RuntimeException('delete_source_outside_document_root');
        }

        $scanResult['planned_action'] = 'delete';
        $scanResult['action'] = 'delete';
        $scanResult['action_status'] = 'pending';

        $item = $this->quarantine($sourcePath, $scanResult, $scanId);
        $id = (string)$item['id'];

        $item['planned_action'] = 'delete';
        $item['action'] = 'delete';
        $item['action_status'] = 'pending';
        $item['deleted_from_original'] = true;
        $this->writeMetadata($this->getMetaPath($id), $item);

        try {
            $item = $this->deletePayload($id, [
                'event' => 'delete_original',
                'source' => 'scanner',
            ]);
        } catch (RuntimeException $exception) {
            try {
                $failedItem = $this->load($id);
                $failedItem['planned_action'] = 'delete';
                $failedItem['action'] = 'delete';
                $failedItem['action_status'] = 'failed';
                $failedItem['action_error'] = $exception->getMessage();
                $failedItem['deleted_from_original'] = true;
                $this->writeMetadata($this->getMetaPath($id), $failedItem);
            } catch (RuntimeException $metadataException) {
                // Keep the original delete error; failed metadata update is secondary here.
            }

            throw $exception;
        }

            $item['planned_action'] = 'delete';
            $item['action'] = 'delete';
            $item['action_status'] = 'done';
            $item['deleted_from_original'] = true;
            $this->writeMetadata($this->getMetaPath($id), $item);

        return $item;
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
                $item['critical_restore'] = !empty($item['original_path']) && $this->isCriticalRestorePath((string)$item['original_path']);
                $items[] = $item;
            } catch (RuntimeException $exception) {
                continue;
            }
        }

        return $items;
    }

    public function restore(string $id, bool $confirmCritical = false, array $context = []): array
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

        $isCriticalRestore = $this->isCriticalRestorePath($originalPath);

        if ($isCriticalRestore && !$confirmCritical) {
            throw new RuntimeException('quarantine_restore_critical_confirmation_required');
        }

        $payloadHash = $this->hashFile($payloadPath);
        $storedPayloadHash = $this->storedPayloadHash($item);

        if ($storedPayloadHash !== '' && !$this->hashesMatch($storedPayloadHash, $payloadHash)) {
            throw new RuntimeException('quarantine_payload_checksum_mismatch');
        }

        $targetDirectory = dirname($originalPath);

        if (!is_dir($targetDirectory) || !is_writable($targetDirectory)) {
            throw new RuntimeException('quarantine_restore_directory_not_writable');
        }

        if (is_file($originalPath) || is_dir($originalPath)) {
            throw new RuntimeException('quarantine_restore_target_exists');
        }

        $move = $this->moveFile($payloadPath, $originalPath, $payloadHash);

        $item['status'] = self::STATUS_RESTORED;
        $item['restored_at'] = date('c');
        $item['restore_payload_hash_before'] = (string)$move['source_hash'];
        $item['restore_file_hash_after'] = (string)$move['target_hash'];
        $item['restore_checksum_verified'] = $this->hashesMatch((string)$move['source_hash'], (string)$move['target_hash']);
        $item['critical_restore'] = $isCriticalRestore;
        $item['critical_restore_confirmed'] = $isCriticalRestore && $confirmCritical;
        $item = $this->appendEvent($item, 'restore', array_merge($context, [
            'critical_restore' => $isCriticalRestore,
            'checksum_verified' => $item['restore_checksum_verified'],
        ]));
        $this->writeMetadata($this->getMetaPath($id), $item);

        return $item;
    }

    public function deletePayload(string $id, array $context = []): array
    {
        $item = $this->load($id);

        if ((string)($item['status'] ?? '') !== self::STATUS_QUARANTINED) {
            throw new RuntimeException('quarantine_item_not_active');
        }

        $payloadPath = isset($item['quarantine_path']) ? (string)$item['quarantine_path'] : '';
        $payloadHash = '';

        if ($payloadPath !== '' && is_file($payloadPath)) {
            $payloadHash = $this->hashFile($payloadPath);
            $storedPayloadHash = $this->storedPayloadHash($item);

            if ($storedPayloadHash !== '' && !$this->hashesMatch($storedPayloadHash, $payloadHash)) {
                throw new RuntimeException('quarantine_payload_checksum_mismatch');
            }

            if (!@unlink($payloadPath)) {
                throw new RuntimeException('quarantine_payload_delete_failed');
            }
        }

        $item['status'] = self::STATUS_DELETED;
        $item['deleted_at'] = date('c');
        $item['payload_hash_before_delete'] = $payloadHash;
        $item['payload_checksum_verified_before_delete'] = $payloadHash !== '';
        $item = $this->appendEvent($item, isset($context['event']) ? (string)$context['event'] : 'delete_payload', $context);
        $this->writeMetadata($this->getMetaPath($id), $item);

        return $item;
    }

    public function load(string $id): array
    {
        return $this->readMetadata($this->getMetaPath($id));
    }

    public function isCriticalRestorePath(string $path): bool
    {
        return $this->isCriticalPath($path);
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
        if (!is_dir($path) && !@mkdir($path, self::DIRECTORY_MODE, true) && !is_dir($path)) {
            throw new RuntimeException('quarantine_directory_create_failed');
        }

        if (!is_writable($path)) {
            throw new RuntimeException('quarantine_directory_not_writable');
        }

        @chmod($path, self::DIRECTORY_MODE);
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

        if (is_file($htaccess)) {
            @chmod($htaccess, self::FILE_MODE);
        }

        if (is_file($index)) {
            @chmod($index, self::FILE_MODE);
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
        @chmod(dirname($path), self::DIRECTORY_MODE);

        $json = json_encode($metadata, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('quarantine_metadata_encode_failed');
        }

        if (file_put_contents($path, $json, LOCK_EX) === false) {
            throw new RuntimeException('quarantine_metadata_save_failed');
        }

        @chmod($path, self::FILE_MODE);
    }

    private function moveFile(string $sourcePath, string $targetPath, string $expectedHash = ''): array
    {
        $sourceHash = $expectedHash !== '' ? $expectedHash : $this->hashFile($sourcePath);

        if (@rename($sourcePath, $targetPath)) {
            $targetHash = $this->hashFile($targetPath);

            if (!$this->hashesMatch($sourceHash, $targetHash)) {
                if (!is_file($sourcePath)) {
                    @rename($targetPath, $sourcePath);
                }

                throw new RuntimeException('quarantine_file_checksum_mismatch');
            }

            return [
                'source_hash' => $sourceHash,
                'target_hash' => $targetHash,
            ];
        }

        if (!@copy($sourcePath, $targetPath)) {
            throw new RuntimeException('quarantine_file_move_failed');
        }

        $targetHash = $this->hashFile($targetPath);

        if (!$this->hashesMatch($sourceHash, $targetHash)) {
            @unlink($targetPath);
            throw new RuntimeException('quarantine_file_checksum_mismatch');
        }

        if (!@unlink($sourcePath)) {
            @unlink($targetPath);
            throw new RuntimeException('quarantine_source_delete_failed');
        }

        return [
            'source_hash' => $sourceHash,
            'target_hash' => $targetHash,
        ];
    }

    private function hashFile(string $path): string
    {
        $hash = @hash_file('sha256', $path);

        return $hash === false ? '' : $hash;
    }

    private function hashesMatch(string $left, string $right): bool
    {
        return $left !== '' && $right !== '' && hash_equals($left, $right);
    }

    private function storedPayloadHash(array $item): string
    {
        if (!empty($item['payload_hash_after'])) {
            return (string)$item['payload_hash_after'];
        }

        return isset($item['file_hash']) ? (string)$item['file_hash'] : '';
    }

    private function appendEvent(array $item, string $event, array $context = []): array
    {
        $events = isset($item['events']) && is_array($item['events']) ? $item['events'] : [];
        $events[] = [
            'event' => $event,
            'created_at' => date('c'),
            'user_id' => isset($context['user_id']) ? (int)$context['user_id'] : 0,
            'source' => isset($context['source']) ? (string)$context['source'] : '',
            'critical_restore' => !empty($context['critical_restore']),
            'checksum_verified' => !empty($context['checksum_verified']),
        ];
        $item['events'] = $events;

        return $item;
    }

    private function isCriticalPath(string $path): bool
    {
        $normalizedPath = $this->normalizePath($path);
        $documentRoot = $this->documentRoot !== '' ? $this->normalizePath($this->documentRoot) : '';

        if ($documentRoot !== '' && $normalizedPath === $documentRoot . '/index.php') {
            return true;
        }

        $patterns = [
            '#(^|/)\.htaccess$#',
            '#(^|/)\.user\.ini$#',
            '#(^|/)php\.ini$#',
            '#/bitrix/\.settings\.php$#',
            '#/bitrix/php_interface/(dbconn|init)\.php$#',
            '#/local/php_interface/(dbconn|init)\.php$#',
            '#/bitrix/(admin|modules|tools)/#',
            '#/local/modules/#',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $normalizedPath)) {
                return true;
            }
        }

        return false;
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
