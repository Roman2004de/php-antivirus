<?php

namespace Delement\Antivirus\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Detector;
use Delement\Antivirus\Detection\RuleEngine;
use Delement\Antivirus\Detection\SignatureLoader;
use Delement\Antivirus\File\FileCollector;
use Delement\Antivirus\File\FileReader;
use Delement\Antivirus\File\FileTypeDetector;
use RuntimeException;
use Throwable;

class Scanner
{
    private $collector;
    private $reader;
    private $fileTypeDetector;
    private $detector;
    private $signatureLoader;
    private $detectors = [];

    public function __construct(FileCollector $collector = null, FileReader $reader = null, Detector $detector = null, FileTypeDetector $fileTypeDetector = null)
    {
        $this->collector = $collector ?: new FileCollector();
        $this->reader = $reader ?: new FileReader();
        $this->fileTypeDetector = $fileTypeDetector ?: new FileTypeDetector();
        $this->detector = $detector;
        $this->signatureLoader = new SignatureLoader();
    }

    public function scan(ScanConfig $config): ScanSummary
    {
        $summary = new ScanSummary($config->getPath());

        try {
            foreach ($this->collector->collectFromConfig($config) as $filePath) {
                $summary->addResult($this->scanFile((string)$filePath, $config));
            }
        } catch (Throwable $exception) {
            $summary->addRuntimeError($config->getPath(), $exception->getMessage());
        }

        $summary->finish();

        return $summary;
    }

    public function scanFile(string $filePath, ScanConfig $config): ScanResult
    {
        try {
            $chunks = $this->reader->readChunks($filePath, $config->getMaxFileSizeBytes());

            return $this->getDetector($config)
                ->detect($filePath, $chunks, $config)
                ->withNormalizedHash($this->calculateNormalizedHash($filePath, $config));
        } catch (RuntimeException $exception) {
            return ScanResult::error($filePath, $exception->getMessage());
        } catch (Throwable $exception) {
            return ScanResult::error($filePath, 'unexpected_scan_error');
        }
    }

    private function getDetector(ScanConfig $config): Detector
    {
        if ($this->detector !== null) {
            return $this->detector;
        }

        $signaturesPath = $config->getSignaturesPath();
        $cacheKey = $signaturesPath !== '' ? $signaturesPath : '__default__';

        if (!isset($this->detectors[$cacheKey])) {
            $rules = $this->signatureLoader->loadDefaultRules();

            if ($signaturesPath !== '') {
                $rules = array_merge($rules, $this->signatureLoader->loadFromFile($signaturesPath));
            }

            $this->detectors[$cacheKey] = new Detector(new RuleEngine($rules));
        }

        return $this->detectors[$cacheKey];
    }

    private function calculateNormalizedHash(string $filePath, ScanConfig $config): ?string
    {
        if (!$config->isNormalizedHashEnabled()) {
            return null;
        }

        $size = @filesize($filePath);

        if ($size === false || $size > $config->getNormalizedHashMaxFileSizeBytes()) {
            return null;
        }

        if ($this->fileTypeDetector->isBinary($filePath)) {
            return null;
        }

        $content = @file_get_contents($filePath);

        if ($content === false || strpos($content, "\0") !== false) {
            return null;
        }

        $normalized = preg_replace('/\s+/', '', $content);

        if ($normalized === null) {
            return null;
        }

        return hash('sha256', $normalized);
    }
}
