<?php

namespace Delement\Antivirus\Detection;

class SignatureLoader
{
    private const RULE_FILES = [
        'php.php',
        'javascript.php',
        'html.php',
        'bitrix.php',
    ];

    private $rulesPath;

    public function __construct(string $rulesPath = null)
    {
        $this->rulesPath = $rulesPath ?: dirname(__DIR__) . '/Rules';
    }

    public function loadDefaultRules(): array
    {
        $rules = [];

        foreach (self::RULE_FILES as $file) {
            $path = rtrim($this->rulesPath, '/\\') . DIRECTORY_SEPARATOR . $file;

            if (!is_file($path)) {
                continue;
            }

            $loaded = require $path;

            if (is_array($loaded)) {
                $rules = array_merge($rules, $loaded);
            }
        }

        return $this->filterValidRules($rules);
    }

    public function loadFromFile(string $path): array
    {
        if (!is_file($path) || !is_readable($path)) {
            return [];
        }

        $lines = file($path, FILE_IGNORE_NEW_LINES);

        if ($lines === false) {
            return [];
        }

        $rules = [];
        $index = 1;

        foreach ($lines as $line) {
            $line = trim((string)$line);

            if ($line === '' || strpos($line, '#') === 0) {
                continue;
            }

            $commentPosition = strpos($line, ' #');

            if ($commentPosition !== false) {
                $line = trim(substr($line, 0, $commentPosition));
            }

            if ($line === '') {
                continue;
            }

            $rules[] = [
                'id' => 'external_signature_' . $index,
                'category' => 'external',
                'severity' => Severity::MEDIUM,
                'score' => 3,
                'pattern' => $line,
            ];
            $index++;
        }

        return $this->filterValidRules($rules);
    }

    public function isValidRegex(string $pattern): bool
    {
        set_error_handler(static function () {
        });
        $result = preg_match($pattern, '');
        restore_error_handler();

        return $result !== false;
    }

    private function filterValidRules(array $rules): array
    {
        $valid = [];
        $seen = [];

        foreach ($rules as $rule) {
            if (!is_array($rule) || empty($rule['id'])) {
                continue;
            }

            $id = (string)$rule['id'];

            if (isset($seen[$id])) {
                continue;
            }

            if (!empty($rule['pattern']) && !$this->isValidRegex((string)$rule['pattern'])) {
                continue;
            }

            $valid[] = $rule;
            $seen[$id] = true;
        }

        return $valid;
    }
}
