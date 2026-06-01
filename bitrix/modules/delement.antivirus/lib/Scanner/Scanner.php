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

    public function __construct(FileCollector $collector = null, FileReader $reader = null, Detector $detector = null)
    {
        $loader = new SignatureLoader();
        $ruleEngine = new RuleEngine($loader->loadDefaultRules());

        $this->collector = $collector ?: new FileCollector();
        $this->reader = $reader ?: new FileReader();
        $this->detector = $detector ?: new Detector($ruleEngine);
    }

    public function scan(ScanConfig $config): ScanSummary
    {
        $summary = new ScanSummary($config->getPath());

        try {
            foreach ($this->collector->collect($config->getPath(), $config) as $filePath) {
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

            return $this->detector->detect($filePath, $chunks, $config);
        } catch (RuntimeException $exception) {
            return ScanResult::error($filePath, $exception->getMessage());
        } catch (Throwable $exception) {
            return ScanResult::error($filePath, 'Unexpected scan error: ' . $exception->getMessage());
        }
    }
}
