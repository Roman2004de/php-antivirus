<?php

namespace Delement\Antivirus\Whitelist;

use Delement\Antivirus\Storage\RuntimeDirectory;
use RuntimeException;

class SuppressionStore
{
    private const FILE_MODE = 0600;

    private $path;

    public function __construct(string $moduleRoot = null)
    {
        $moduleRoot = $moduleRoot ?: dirname(__DIR__, 2);
        $this->path = RuntimeDirectory::resolve($moduleRoot, 'whitelist') . DIRECTORY_SEPARATOR . 'finding_suppressions.json';
    }

    public function listItems(): array
    {
        if (!is_file($this->path)) {
            return [];
        }

        $data = json_decode((string)file_get_contents($this->path), true);

        if (!is_array($data) || !isset($data['items']) || !is_array($data['items'])) {
            return [];
        }

        $items = [];

        foreach ($data['items'] as $item) {
            if (!is_array($item)) {
                continue;
            }

            $fingerprint = strtolower(trim((string)($item['fingerprint'] ?? '')));

            if (!$this->isFingerprint($fingerprint)) {
                continue;
            }

            $item['fingerprint'] = $fingerprint;
            $items[] = $item;
        }

        return $items;
    }

    public function has(string $fingerprint): bool
    {
        $fingerprint = strtolower(trim($fingerprint));

        if (!$this->isFingerprint($fingerprint)) {
            return false;
        }

        foreach ($this->listItems() as $item) {
            if ((string)($item['fingerprint'] ?? '') === $fingerprint) {
                return true;
            }
        }

        return false;
    }

    public function add(array $item): array
    {
        $item = $this->normalizeItem($item);
        $items = $this->listItems();

        foreach ($items as $existingItem) {
            if ((string)($existingItem['fingerprint'] ?? '') === $item['fingerprint']) {
                return $existingItem;
            }
        }

        $items[] = $item;
        $this->save($items);

        return $item;
    }

    public function delete(string $fingerprint): bool
    {
        $fingerprint = strtolower(trim($fingerprint));

        if (!$this->isFingerprint($fingerprint)) {
            throw new RuntimeException('suppression_fingerprint_invalid');
        }

        $items = [];
        $deleted = false;

        foreach ($this->listItems() as $item) {
            if ((string)($item['fingerprint'] ?? '') === $fingerprint) {
                $deleted = true;
                continue;
            }

            $items[] = $item;
        }

        if ($deleted) {
            $this->save($items);
        }

        return $deleted;
    }

    private function normalizeItem(array $item): array
    {
        $fingerprint = strtolower(trim((string)($item['fingerprint'] ?? '')));

        if (!$this->isFingerprint($fingerprint)) {
            throw new RuntimeException('suppression_fingerprint_invalid');
        }

        return [
            'fingerprint' => $fingerprint,
            'scope' => 'finding',
            'file_path' => (string)($item['file_path'] ?? ''),
            'signature_id' => (string)($item['signature_id'] ?? ''),
            'target' => (string)($item['target'] ?? 'content'),
            'excerpt_hash' => (string)($item['excerpt_hash'] ?? ''),
            'created_at' => (string)($item['created_at'] ?? date('c')),
            'created_by' => (int)($item['created_by'] ?? 0),
            'comment' => trim((string)($item['comment'] ?? '')),
        ];
    }

    private function save(array $items): void
    {
        $payload = [
            'version' => 1,
            'items' => array_values($items),
        ];
        $json = json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        if ($json === false) {
            throw new RuntimeException('suppression_store_encode_failed');
        }

        if (file_put_contents($this->path, $json, LOCK_EX) === false) {
            throw new RuntimeException('suppression_store_save_failed');
        }

        @chmod($this->path, self::FILE_MODE);
    }

    private function isFingerprint(string $fingerprint): bool
    {
        return preg_match('/^[a-f0-9]{64}$/', $fingerprint) === 1;
    }
}
