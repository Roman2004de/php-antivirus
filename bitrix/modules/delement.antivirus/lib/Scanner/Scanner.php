<?php

namespace Delement\Antivirus\Scanner;

use Delement\Antivirus\Config\ScanConfig;
use Delement\Antivirus\Detection\Detector;
use Delement\Antivirus\Detection\RuleEngine;
use Delement\Antivirus\Detection\SignatureLoader;
use Delement\Antivirus\File\FileCollector;
use Delement\Antivirus\File\FileReader;
use RuntimeException;
use Throwable;

class Scanner
{
    private $collector;
    private $reader;
    private $detector;
    private $signatureLoader;
    private $detectors = [];

    public function __construct(FileCollector $collector = null, FileReader $reader = null, Detector $detector = null)
    {
        $this->collector = $collector ?: new FileCollector();
        $this->reader = $reader ?: new FileReader();
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

            return $this->getDetector($config)->detect($filePath, $chunks, $config);
        } catch (RuntimeException $exception) {
            return ScanResult::error($filePath, $exception->getMessage());
        } catch (Throwable $exception) {
            return ScanResult::error($filePath, 'Unexpected scan error: ' . $exception->getMessage());
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
}
