<?php

namespace Delement\Antivirus\File;

class FileTypeDetector
{
    private const BINARY_FORMATS = [
        'exe' => "\x4D\x5A",
        'png' => "\x89\x50\x4E\x47",
        'jpg' => "\xFF\xD8\xFF",
        'zip' => "\x50\x4B\x03\x04",
        'pdf' => "\x25\x50\x44\x46",
        'rar' => "\x52\x61\x72\x21",
        'gif' => "\x47\x49\x46\x38",
        'elf' => "\x7F\x45\x4C\x46",
        'mp3' => "\x49\x44\x33",
        'mp4' => "\x00\x00\x00\x18\x66\x74\x79\x70",
    ];

    public function isBinary(string $filePath): bool
    {
        $maxSignatureLength = 0;

        foreach (self::BINARY_FORMATS as $signature) {
            $maxSignatureLength = max($maxSignatureLength, strlen($signature));
        }

        if ($maxSignatureLength <= 0) {
            return false;
        }

        $header = @file_get_contents($filePath, false, null, 0, $maxSignatureLength);

        if ($header === false || $header === '') {
            return false;
        }

        foreach (self::BINARY_FORMATS as $signature) {
            if (strpos($header, $signature) === 0) {
                return true;
            }
        }

        return false;
    }
}
