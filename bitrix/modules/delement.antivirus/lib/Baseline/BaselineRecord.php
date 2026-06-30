<?php

namespace Delement\Antivirus\Baseline;

class BaselineRecord
{
    private $path;
    private $relativePath;
    private $size;
    private $mtime;
    private $sha256;
    private $normalizedHash;
    private $createdAt;

    public function __construct(array $data)
    {
        $this->path = isset($data['path']) ? (string)$data['path'] : '';
        $this->relativePath = isset($data['relative_path']) ? (string)$data['relative_path'] : '';
        $this->size = isset($data['size']) ? (int)$data['size'] : 0;
        $this->mtime = isset($data['mtime']) ? (int)$data['mtime'] : 0;
        $this->sha256 = isset($data['sha256']) ? (string)$data['sha256'] : '';
        $this->normalizedHash = array_key_exists('normalized_hash', $data) && $data['normalized_hash'] !== null
            ? (string)$data['normalized_hash']
            : null;
        $this->createdAt = isset($data['created_at']) ? (string)$data['created_at'] : date('c');
    }

    public static function fromArray(array $data): self
    {
        return new self($data);
    }

    public function getPath(): string
    {
        return $this->path;
    }

    public function getRelativePath(): string
    {
        return $this->relativePath;
    }

    public function getSize(): int
    {
        return $this->size;
    }

    public function getMtime(): int
    {
        return $this->mtime;
    }

    public function getSha256(): string
    {
        return $this->sha256;
    }

    public function getNormalizedHash(): ?string
    {
        return $this->normalizedHash;
    }

    public function getCreatedAt(): string
    {
        return $this->createdAt;
    }

    public function toArray(): array
    {
        return [
            'path' => $this->path,
            'relative_path' => $this->relativePath,
            'size' => $this->size,
            'mtime' => $this->mtime,
            'sha256' => $this->sha256,
            'normalized_hash' => $this->normalizedHash,
            'created_at' => $this->createdAt,
        ];
    }
}
