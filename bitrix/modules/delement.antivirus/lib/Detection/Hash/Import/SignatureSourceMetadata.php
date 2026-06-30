<?php

namespace Delement\Antivirus\Detection\Hash\Import;

class SignatureSourceMetadata
{
    private $name;
    private $url;
    private $license;
    private $importedAt;
    private $sourceCommit;
    private $sourceVersion;

    public function __construct(
        string $name,
        string $url,
        string $license,
        string $importedAt = '',
        string $sourceCommit = '',
        string $sourceVersion = ''
    ) {
        $this->name = $name;
        $this->url = $url;
        $this->license = $license;
        $this->importedAt = $importedAt !== '' ? $importedAt : date('c');
        $this->sourceCommit = $sourceCommit;
        $this->sourceVersion = $sourceVersion;
    }

    public static function panelica(string $sourceCommit = '', string $sourceVersion = ''): self
    {
        return new self(
            'Panelica Malware Signatures',
            'https://github.com/Panelica/malware-signatures',
            'MIT',
            date('c'),
            $sourceCommit,
            $sourceVersion
        );
    }

    public function toArray(): array
    {
        $result = [
            'name' => $this->name,
            'url' => $this->url,
            'license' => $this->license,
            'imported_at' => $this->importedAt,
        ];

        if ($this->sourceCommit !== '') {
            $result['source_commit'] = $this->sourceCommit;
        }

        if ($this->sourceVersion !== '') {
            $result['source_version'] = $this->sourceVersion;
        }

        return $result;
    }

    public function toShortArray(): array
    {
        return [
            'name' => $this->name,
            'license' => $this->license,
        ];
    }
}
