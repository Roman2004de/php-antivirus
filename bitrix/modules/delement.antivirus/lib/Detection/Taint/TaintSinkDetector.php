<?php

namespace Delement\Antivirus\Detection\Taint;

use Delement\Antivirus\Detection\Ast\AstContext;
use Delement\Antivirus\Detection\Severity;
use PhpParser\Node;

class TaintSinkDetector
{
    private const ARGUMENT_SINKS = [
        'assert' => [0],
        'system' => [0],
        'exec' => [0],
        'shell_exec' => [0],
        'passthru' => [0],
        'proc_open' => [0],
        'popen' => [0],
        'file_put_contents' => [0, 1],
        'fwrite' => [1],
        'mail' => [0, 1, 2, 3],
        'call_user_func' => [0, 1],
        'call_user_func_array' => [0, 1],
    ];

    private const HIGH_SINKS = [
        'file_put_contents' => true,
        'fwrite' => true,
        'mail' => true,
        'curl_setopt' => true,
        'preg_replace' => true,
        'preg_replace_callback' => true,
        'preg_replace_callback_array' => true,
    ];

    private $propagator;
    private $factory;

    public function __construct(TaintPropagator $propagator = null, TaintFindingFactory $factory = null)
    {
        $this->propagator = $propagator ?: new TaintPropagator();
        $this->factory = $factory ?: new TaintFindingFactory();
    }

    public function detect(AstContext $context, array $taints): array
    {
        $findings = [];

        foreach ($context->evalNodes as $eval) {
            $trace = $this->propagator->traceForExpression($eval['expr'], $context, $taints);

            if ($trace !== null) {
                $findings[] = $this->factory->create($trace->withSink('eval', (int)$eval['line'], Severity::CRITICAL));
            }
        }

        foreach ($context->includes as $include) {
            $trace = $this->propagator->traceForExpression($include['expr'], $context, $taints);

            if ($trace !== null) {
                $findings[] = $this->factory->create($trace->withSink((string)$include['type'], (int)$include['line'], Severity::CRITICAL));
            }
        }

        foreach ($context->calls as $call) {
            $findings = array_merge($findings, $this->detectFunctionCall($call, $context, $taints));
        }

        foreach ($context->variableFunctionCalls as $call) {
            $trace = $this->traceDynamicCall($call, $context, $taints);

            if ($trace !== null) {
                $findings[] = $this->factory->create($trace->withSink('dynamic_call', (int)$call['line'], Severity::CRITICAL));
            }
        }

        return $findings;
    }

    private function detectFunctionCall(array $call, AstContext $context, array $taints): array
    {
        $name = isset($call['name']) ? strtolower((string)$call['name']) : '';

        if ($name === '') {
            return [];
        }

        if ($name === 'curl_setopt') {
            return $this->detectCurlSetopt($call, $context, $taints);
        }

        if (in_array($name, ['preg_replace', 'preg_replace_callback', 'preg_replace_callback_array'], true)) {
            return $this->detectPregSink($name, $call, $context, $taints);
        }

        if (!isset(self::ARGUMENT_SINKS[$name])) {
            return [];
        }

        foreach (self::ARGUMENT_SINKS[$name] as $position) {
            if (empty($call['args'][$position]->value)) {
                continue;
            }

            $trace = $this->propagator->traceForExpression($call['args'][$position]->value, $context, $taints);

            if ($trace !== null) {
                return [
                    $this->factory->create($trace->withSink($name, (int)$call['line'], $this->sinkSeverity($name))),
                ];
            }
        }

        return [];
    }

    private function detectCurlSetopt(array $call, AstContext $context, array $taints): array
    {
        if (empty($call['args'][1]->value) || empty($call['args'][2]->value)) {
            return [];
        }

        $option = strtoupper((string)$context->resolveString($call['args'][1]->value));

        if ($option !== 'CURLOPT_URL') {
            return [];
        }

        $trace = $this->propagator->traceForExpression($call['args'][2]->value, $context, $taints);

        if ($trace === null) {
            return [];
        }

        return [
            $this->factory->create($trace->withSink('curl_setopt_url', (int)$call['line'], Severity::HIGH)),
        ];
    }

    private function detectPregSink(string $name, array $call, AstContext $context, array $taints): array
    {
        if ($name === 'preg_replace') {
            $isEvalPattern = !empty($call['args'][0]->value) && $this->isPregReplaceEvalPattern((string)$context->resolveString($call['args'][0]->value));

            if (!$isEvalPattern) {
                return [];
            }

            foreach ([1, 2] as $position) {
                if (empty($call['args'][$position]->value)) {
                    continue;
                }

                $trace = $this->propagator->traceForExpression($call['args'][$position]->value, $context, $taints);

                if ($trace !== null) {
                    return [
                        $this->factory->create($trace->withSink('preg_replace_eval', (int)$call['line'], Severity::HIGH)),
                    ];
                }
            }

            return [];
        }

        $callbackPosition = $name === 'preg_replace_callback_array' ? 0 : 1;

        if (empty($call['args'][$callbackPosition]->value)) {
            return [];
        }

        $trace = $this->propagator->traceForExpression($call['args'][$callbackPosition]->value, $context, $taints);

        if ($trace === null) {
            return [];
        }

        return [
            $this->factory->create($trace->withSink($name, (int)$call['line'], Severity::HIGH)),
        ];
    }

    private function traceDynamicCall(array $call, AstContext $context, array $taints): ?TaintTrace
    {
        if (!$call['node'] instanceof Node\Expr\FuncCall) {
            return null;
        }

        $trace = $this->propagator->traceForExpression($call['node']->name, $context, $taints);

        if ($trace !== null) {
            return $trace;
        }

        foreach ($call['args'] as $argument) {
            $trace = $this->propagator->traceForExpression($argument->value, $context, $taints);

            if ($trace !== null) {
                return $trace;
            }
        }

        return null;
    }

    private function sinkSeverity(string $name): string
    {
        return isset(self::HIGH_SINKS[$name]) ? Severity::HIGH : Severity::CRITICAL;
    }

    private function isPregReplaceEvalPattern(string $pattern): bool
    {
        if ($pattern === '') {
            return false;
        }

        return preg_match('/([~#\/%!]).*\1[imsxuADSUXJ]*e[imsxuADSUXJ]*$/s', $pattern) === 1;
    }
}
