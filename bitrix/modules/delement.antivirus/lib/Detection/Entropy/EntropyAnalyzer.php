<?php

namespace Delement\Antivirus\Detection\Entropy;

use Delement\Antivirus\Config\ScanConfig;

class EntropyAnalyzer
{
    private const DANGEROUS_MARKERS = [
        'eval',
        'assert',
        'base64_decode',
        'gzinflate',
        'gzuncompress',
        'str_rot13',
        'create_function',
        'atob',
        'fromCharCode',
        'Function(',
    ];

    private $calculator;
    private $factory;

    public function __construct(EntropyCalculator $calculator = null, EntropyFindingFactory $factory = null)
    {
        $this->calculator = $calculator ?: new EntropyCalculator();
        $this->factory = $factory ?: new EntropyFindingFactory();
    }

    public function analyze(string $content, string $filePath, ScanConfig $config): array
    {
        $minLength = $config->getEntropyMinLength();
        $threshold = $config->getEntropyThreshold();
        $contextWindow = $config->getEntropyContextWindow();
        $findings = [];
        $seen = [];

        foreach ($this->extractCandidates($content, $minLength) as $candidate) {
            $value = (string)$candidate['value'];
            $offset = (int)$candidate['offset'];
            $length = strlen($value);

            if ($length < $minLength) {
                continue;
            }

            $entropy = $this->calculator->shannon($value);

            if ($entropy < $threshold) {
                continue;
            }

            $context = $this->context($content, $offset, $length, $contextWindow);
            $hasDangerousContext = $this->hasDangerousMarker($context);

            if (!$hasDangerousContext && !$this->looksEncoded($value)) {
                continue;
            }

            $key = $offset . ':' . sha1(substr($value, 0, 512));

            if (isset($seen[$key])) {
                continue;
            }

            $seen[$key] = true;
            $findings[] = $this->factory->highEncodedPayload(
                $filePath,
                $offset,
                $this->excerpt($value),
                $entropy,
                $length,
                $hasDangerousContext
            );
        }

        return $findings;
    }

    private function extractCandidates(string $content, int $minLength): array
    {
        $candidates = [];

        foreach ([
            '/[A-Za-z0-9+\/=]{' . $minLength . ',}/',
            '/\b[0-9a-fA-F]{' . $minLength . ',}\b/',
            '/(["\'])(.{' . $minLength . ',}?)\1/s',
        ] as $pattern) {
            if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE) !== 1) {
                continue;
            }

            foreach ($matches[0] as $index => $match) {
                $value = (string)$match[0];
                $offset = (int)$match[1];

                if (isset($matches[2][$index])) {
                    $value = (string)$matches[2][$index][0];
                    $offset = (int)$matches[2][$index][1];
                }

                $candidates[] = [
                    'value' => $value,
                    'offset' => $offset,
                ];
            }
        }

        return $candidates;
    }

    private function hasDangerousMarker(string $context): bool
    {
        foreach (self::DANGEROUS_MARKERS as $marker) {
            if (stripos($context, $marker) !== false) {
                return true;
            }
        }

        return false;
    }

    private function looksEncoded(string $value): bool
    {
        if (preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $value) === 1 && strlen($value) % 4 === 0) {
            return true;
        }

        if (preg_match('/^(?:[0-9a-fA-F]{2})+$/', $value) === 1) {
            return true;
        }

        return false;
    }

    private function context(string $content, int $offset, int $length, int $window): string
    {
        $start = max(0, $offset - $window);
        $end = min(strlen($content), $offset + $length + $window);

        return substr($content, $start, $end - $start);
    }

    private function excerpt(string $value): string
    {
        $value = preg_replace('/\s+/', ' ', $value);

        if ($value === null) {
            $value = '';
        }

        if (strlen($value) <= 160) {
            return $value;
        }

        return substr($value, 0, 120) . '...' . substr($value, -32);
    }
}
