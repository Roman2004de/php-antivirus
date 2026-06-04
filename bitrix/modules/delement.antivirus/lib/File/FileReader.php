<?php

namespace Delement\Antivirus\File;

use RuntimeException;

class FileReader
{
    private $blockSize;
    private $overlapSize;

    public function __construct(int $blockSize = 32768, int $overlapSize = 512)
    {
        $this->blockSize = $blockSize;
        $this->overlapSize = $overlapSize;
    }

    public function readChunks(string $filePath, int $maxFileSizeBytes): iterable
    {
        $size = @filesize($filePath);

        if ($size === false) {
            throw new RuntimeException('file_size_unavailable');
        }

        if ($size <= $maxFileSizeBytes) {
            $content = @file_get_contents($filePath);

            if ($content === false) {
                throw new RuntimeException('file_read_failed');
            }

            yield $content;
            return;
        }

        $handle = @fopen($filePath, 'rb');

        if ($handle === false) {
            throw new RuntimeException('large_file_open_failed');
        }

        $buffer = '';

        try {
            while (!feof($handle)) {
                $chunk = fread($handle, $this->blockSize);

                if ($chunk === false) {
                    throw new RuntimeException('large_file_chunk_read_failed');
                }

                if ($chunk === '') {
                    break;
                }

                $buffer .= $chunk;
                yield $buffer;
                $buffer = substr($buffer, -$this->overlapSize);
            }
        } finally {
            fclose($handle);
        }
    }
}
