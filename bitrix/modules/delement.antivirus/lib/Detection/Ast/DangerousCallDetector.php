<?php

namespace Delement\Antivirus\Detection\Ast;

use Delement\Antivirus\Detection\Severity;

class DangerousCallDetector
{
    private const SINKS = [
        'assert' => [Severity::HIGH, 8],
        'system' => [Severity::CRITICAL, 9],
        'exec' => [Severity::CRITICAL, 9],
        'shell_exec' => [Severity::CRITICAL, 9],
        'passthru' => [Severity::CRITICAL, 9],
        'proc_open' => [Severity::CRITICAL, 9],
        'popen' => [Severity::CRITICAL, 9],
        'pcntl_exec' => [Severity::CRITICAL, 9],
        'file_put_contents' => [Severity::HIGH, 6],
        'fwrite' => [Severity::HIGH, 6],
        'create_function' => [Severity::HIGH, 8],
        'call_user_func' => [Severity::HIGH, 7],
        'call_user_func_array' => [Severity::HIGH, 7],
    ];

    private $factory;

    public function __construct(AstFindingFactory $factory = null)
    {
        $this->factory = $factory ?: new AstFindingFactory();
    }

    public function detect(AstContext $context): array
    {
        $findings = [];

        foreach ($context->evalNodes as $eval) {
            $findings[] = $this->factory->dangerousCall(
                'eval',
                Severity::CRITICAL,
                10,
                (int)$eval['line'],
                $context->expressionLabel($eval['expr'])
            );
        }

        foreach ($context->includes as $include) {
            $severity = $context->containsSuperglobal($include['expr']) ? Severity::CRITICAL : Severity::HIGH;
            $score = $severity === Severity::CRITICAL ? 9 : 6;
            $findings[] = $this->factory->dangerousCall(
                (string)$include['type'],
                $severity,
                $score,
                (int)$include['line'],
                $context->expressionLabel($include['expr'])
            );
        }

        foreach ($context->calls as $call) {
            $name = isset($call['name']) ? strtolower((string)$call['name']) : '';

            if ($name === '') {
                continue;
            }

            if ($name === 'preg_replace' && $this->isPregReplaceEval($context, $call)) {
                $findings[] = $this->factory->dangerousCall('preg_replace_eval', Severity::CRITICAL, 9, (int)$call['line'], 'preg_replace /e');
                continue;
            }

            if (!isset(self::SINKS[$name])) {
                continue;
            }

            $findings[] = $this->factory->dangerousCall(
                $name,
                self::SINKS[$name][0],
                self::SINKS[$name][1],
                (int)$call['line'],
                $this->callExcerpt($context, $call)
            );
        }

        foreach ($context->staticCalls as $call) {
            $class = strtolower(trim((string)($call['class'] ?? ''), '\\'));
            $name = strtolower((string)($call['name'] ?? ''));

            if ($class === 'reflectionfunction' && $name === 'invoke') {
                $findings[] = $this->factory->dangerousCall('reflectionfunction_invoke', Severity::HIGH, 8, (int)$call['line'], 'ReflectionFunction::invoke');
            }
        }

        return $findings;
    }

    private function isPregReplaceEval(AstContext $context, array $call): bool
    {
        if (empty($call['args'][0]->value)) {
            return false;
        }

        $pattern = $context->resolveString($call['args'][0]->value);

        if ($pattern === null || $pattern === '') {
            return false;
        }

        return preg_match('/([~#\/%!]).*\1[imsxuADSUXJ]*e[imsxuADSUXJ]*$/s', $pattern) === 1;
    }

    private function callExcerpt(AstContext $context, array $call): string
    {
        if (empty($call['args'][0]->value)) {
            return (string)($call['name'] ?? '');
        }

        return (string)($call['name'] ?? '') . '(' . $context->expressionLabel($call['args'][0]->value) . ')';
    }
}
