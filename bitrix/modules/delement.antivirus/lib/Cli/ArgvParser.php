<?php

namespace Delement\Antivirus\Cli;

use InvalidArgumentException;

class ArgvParser
{
    private const FLAGS = [
        'dry-run' => true,
        'no-dry-run' => true,
        'json' => true,
        'help' => true,
        'version' => true,
        'force' => true,
        'enable-ast' => true,
        'disable-ast' => true,
        'enable-prefilter' => true,
        'disable-prefilter' => true,
        'enable-normalized-hash' => true,
        'disable-normalized-hash' => true,
    ];

    private const VALUE_OPTIONS = [
        'path' => true,
        'document-root' => true,
        'scan-profile' => true,
        'profile' => true,
        'action' => true,
        'signatures' => true,
        'exclude' => true,
        'report' => true,
        'batch-size' => true,
        'max-file-size-mb' => true,
        'normalized-hash-max-file-size-mb' => true,
        'ast-max-file-size' => true,
        'quarantine-path' => true,
    ];

    public function parse(array $argv): array
    {
        $options = [];
        $flags = [];
        $positionals = [];
        $count = count($argv);

        for ($index = 1; $index < $count; $index++) {
            $argument = (string)$argv[$index];

            if ($argument === '') {
                continue;
            }

            if ($argument === '--') {
                for ($position = $index + 1; $position < $count; $position++) {
                    $positionals[] = (string)$argv[$position];
                }

                break;
            }

            if (strpos($argument, '--') !== 0) {
                $positionals[] = $argument;
                continue;
            }

            $raw = substr($argument, 2);
            $name = $raw;
            $value = null;
            $equalsPosition = strpos($raw, '=');

            if ($equalsPosition !== false) {
                $name = substr($raw, 0, $equalsPosition);
                $value = substr($raw, $equalsPosition + 1);
            }

            if (isset(self::FLAGS[$name])) {
                if ($value !== null && $value !== '') {
                    throw new InvalidArgumentException('cli_option_does_not_accept_value:' . $name);
                }

                $flags[$name] = true;
                continue;
            }

            if (!isset(self::VALUE_OPTIONS[$name])) {
                throw new InvalidArgumentException('cli_unknown_option:' . $name);
            }

            if ($value === null) {
                $index++;

                if ($index >= $count) {
                    throw new InvalidArgumentException('cli_option_value_required:' . $name);
                }

                $value = (string)$argv[$index];
            }

            if ($name === 'exclude') {
                if (!isset($options[$name]) || !is_array($options[$name])) {
                    $options[$name] = [];
                }

                $options[$name][] = $value;
                continue;
            }

            $options[$name] = $value;
        }

        if (!empty($positionals)) {
            throw new InvalidArgumentException('cli_unexpected_argument:' . reset($positionals));
        }

        return [
            'options' => $options,
            'flags' => $flags,
        ];
    }
}
