<?php

namespace Delement\Antivirus\Detection;

use Delement\Antivirus\Config\ScanConfig;

class RuleEngine
{
    private $rules;

    public function __construct(array $rules)
    {
        $this->rules = $rules;
    }

    public function analyzePath(string $filePath, ScanConfig $config): array
    {
        $findings = [];

        foreach ($this->rules as $rule) {
            if (!empty($rule['pattern'])) {
                continue;
            }

            if (!$this->matchesPath($rule, $filePath)) {
                continue;
            }

            $findings[] = $this->createFinding($rule, null, '', 'path');
        }

        return $findings;
    }

    public function analyzeContent(string $content, string $filePath, ScanConfig $config): array
    {
        if ($content === '') {
            return [];
        }

        $findings = [];

        foreach ($this->rules as $rule) {
            if (empty($rule['pattern'])) {
                continue;
            }

            if (!$this->matchesPath($rule, $filePath)) {
                continue;
            }

            if ($config->isCommonStringsPrefilterEnabled() && !$this->passesCommonStringsPrefilter($rule, $content)) {
                continue;
            }

            $pattern = (string)$rule['pattern'];

            set_error_handler(static function () {
            });
            $matched = preg_match($pattern, $content, $matches, PREG_OFFSET_CAPTURE);
            restore_error_handler();

            if ($matched !== 1) {
                continue;
            }

            $offset = isset($matches[0][1]) ? (int)$matches[0][1] : 0;
            $excerpt = $this->makeExcerpt($content, $offset);
            $findings[] = $this->createFinding($rule, $offset, $excerpt, 'content');
        }

        return $findings;
    }

    private function matchesPath(array $rule, string $filePath): bool
    {
        $normalizedPath = $this->normalizePath($filePath);

        if (!empty($rule['path_contains'])) {
            $needle = $this->normalizePath((string)$rule['path_contains']);

            if (strpos($normalizedPath, $needle) === false) {
                return false;
            }
        }

        if (!empty($rule['path_equals'])) {
            $needle = $this->normalizePath((string)$rule['path_equals']);

            if (substr($normalizedPath, -strlen($needle)) !== $needle) {
                return false;
            }
        }

        if (!empty($rule['extensions'])) {
            $extension = strtolower(pathinfo($filePath, PATHINFO_EXTENSION));
            $extensions = array_map('strtolower', (array)$rule['extensions']);

            if (!in_array($extension, $extensions, true)) {
                return false;
            }
        }

        return true;
    }

    private function passesCommonStringsPrefilter(array $rule, string $content): bool
    {
        if (!isset($rule['common_strings'])) {
            return true;
        }

        $prefilter = $this->normalizeCommonStrings($rule['common_strings']);

        if (empty($prefilter['values'])) {
            return true;
        }

        $mode = $prefilter['mode'];
        $matched = 0;

        foreach ($prefilter['values'] as $value) {
            if (stripos($content, $value) === false) {
                if ($mode === 'all') {
                    return false;
                }

                continue;
            }

            $matched++;

            if ($mode === 'any') {
                return true;
            }
        }

        return $mode === 'all' && $matched === count($prefilter['values']);
    }

    private function normalizeCommonStrings($commonStrings): array
    {
        if (is_string($commonStrings)) {
            return [
                'mode' => 'any',
                'values' => $this->normalizeCommonStringValues([$commonStrings]),
            ];
        }

        if (!is_array($commonStrings)) {
            return [
                'mode' => 'any',
                'values' => [],
            ];
        }

        $isShortFormat = !array_key_exists('mode', $commonStrings) && !array_key_exists('values', $commonStrings);

        if ($isShortFormat) {
            return [
                'mode' => 'any',
                'values' => $this->normalizeCommonStringValues($commonStrings),
            ];
        }

        $mode = isset($commonStrings['mode']) ? strtolower((string)$commonStrings['mode']) : 'any';
        $mode = $mode === 'all' ? 'all' : 'any';
        $values = isset($commonStrings['values']) ? $commonStrings['values'] : [];
        $values = is_array($values) ? $values : [$values];

        return [
            'mode' => $mode,
            'values' => $this->normalizeCommonStringValues($values),
        ];
    }

    private function normalizeCommonStringValues(array $values): array
    {
        $normalized = [];
        $seen = [];

        foreach ($values as $value) {
            $value = (string)$value;

            if ($value === '') {
                continue;
            }

            $key = strtolower($value);

            if (isset($seen[$key])) {
                continue;
            }

            $normalized[] = $value;
            $seen[$key] = true;
        }

        return $normalized;
    }

    private function createFinding(array $rule, ?int $offset, string $excerpt, string $target): Finding
    {
        return new Finding([
            'signature_id' => isset($rule['id']) ? $rule['id'] : '',
            'name' => isset($rule['name']) ? $rule['name'] : (isset($rule['id']) ? $rule['id'] : ''),
            'category' => isset($rule['category']) ? $rule['category'] : 'generic',
            'severity' => isset($rule['severity']) ? $rule['severity'] : Severity::LOW,
            'score' => isset($rule['score']) ? $rule['score'] : 1,
            'offset' => $offset,
            'excerpt' => $excerpt,
            'target' => $target,
            'rule_type' => empty($rule['pattern']) ? 'path' : 'regex',
        ]);
    }

    private function makeExcerpt(string $content, int $offset): string
    {
        $start = max(0, $offset - 60);
        $excerpt = substr($content, $start, 160);
        $excerpt = preg_replace('/\s+/', ' ', $excerpt);

        return trim((string)$excerpt);
    }

    private function normalizePath(string $path): string
    {
        return str_replace('\\', '/', strtolower($path));
    }
}
