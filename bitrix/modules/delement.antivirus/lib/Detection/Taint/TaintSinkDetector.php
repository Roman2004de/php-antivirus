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

    private const METHOD_ARGUMENT_SINKS = [
        'eval' => [0],
        'assert' => [0],
        'system' => [0],
        'exec' => [0],
        'shell_exec' => [0],
        'passthru' => [0],
        'proc_open' => [0],
        'popen' => [0],
        'invoke' => [0],
        'invokeargs' => [0],
        'query' => [0],
        'multi_query' => [0],
    ];

    private const STATIC_ARGUMENT_SINKS = [
        'eval' => [0],
        'assert' => [0],
        'system' => [0],
        'exec' => [0],
        'shell_exec' => [0],
        'passthru' => [0],
        'proc_open' => [0],
        'popen' => [0],
        'invoke' => [0],
        'invokeargs' => [0],
    ];

    private const HIGH_SINKS = [
        'file_put_contents' => true,
        'fwrite' => true,
        'mail' => true,
        'curl_setopt' => true,
        'preg_replace' => true,
        'preg_replace_callback' => true,
        'preg_replace_callback_array' => true,
        'method_invoke' => true,
        'method_invokeargs' => true,
        'method_query' => true,
        'method_multi_query' => true,
        'reflectionfunction_invoke' => true,
        'reflectionfunction_invokeargs' => true,
        'reflectionmethod_invoke' => true,
        'reflectionmethod_invokeargs' => true,
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

        foreach ($context->nodes as $node) {
            $findings = array_merge($findings, $this->detectNodeSinks($node, $context, $taints));
        }

        return $findings;
    }

    private function detectNodeSinks($node, AstContext $context, array $taints, array $stack = []): array
    {
        if (is_array($node)) {
            $findings = [];

            foreach ($node as $item) {
                $findings = array_merge($findings, $this->detectNodeSinks($item, $context, $taints, $stack));
            }

            return $findings;
        }

        if (!$node instanceof Node) {
            return [];
        }

        if (
            $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Expr\Closure
            || $node instanceof Node\Stmt\Class_
            || $node instanceof Node\Stmt\ClassMethod
            || $node instanceof Node\Stmt\Trait_
            || $node instanceof Node\Stmt\Interface_
        ) {
            return [];
        }

        $findings = [];

        if ($node instanceof Node\Expr\Eval_) {
            $trace = $this->propagator->traceForExpression($node->expr, $context, $taints, $stack);

            if ($trace !== null) {
                $findings[] = $this->factory->create($trace->withSink('eval', $this->line($node), Severity::CRITICAL));
            }
        } elseif ($node instanceof Node\Expr\Include_) {
            $trace = $this->propagator->traceForExpression($node->expr, $context, $taints, $stack);

            if ($trace !== null) {
                $findings[] = $this->factory->create($trace->withSink($this->includeType($node), $this->line($node), Severity::CRITICAL));
            }
        } elseif ($node instanceof Node\Expr\FuncCall) {
            $call = $this->functionCall($node, $context);
            $findings = array_merge($findings, $this->detectFunctionCall($call, $context, $taints, $stack));

            if (!$node->name instanceof Node\Name) {
                $trace = $this->traceDynamicCall($call, $context, $taints, $stack);

                if ($trace !== null) {
                    $findings[] = $this->factory->create($trace->withSink('dynamic_call', $this->line($node), Severity::CRITICAL));
                }
            }

            $findings = array_merge($findings, $this->detectUserFunctionCall($call, $context, $taints, $stack));
        } elseif ($node instanceof Node\Expr\MethodCall) {
            $findings = array_merge($findings, $this->detectMethodCall($this->methodCall($node, $context), $context, $taints, $stack));
        } elseif ($node instanceof Node\Expr\StaticCall) {
            $findings = array_merge($findings, $this->detectStaticCall($this->staticCall($node, $context), $context, $taints, $stack));
        }

        foreach ($node->getSubNodeNames() as $name) {
            $findings = array_merge($findings, $this->detectNodeSinks($node->$name, $context, $taints, $stack));
        }

        return $findings;
    }

    private function detectFunctionCall(array $call, AstContext $context, array $taints, array $stack = []): array
    {
        $name = isset($call['name']) ? strtolower((string)$call['name']) : '';

        if ($name === '') {
            return [];
        }

        if ($name === 'curl_setopt') {
            return $this->detectCurlSetopt($call, $context, $taints, $stack);
        }

        if (in_array($name, ['preg_replace', 'preg_replace_callback', 'preg_replace_callback_array'], true)) {
            return $this->detectPregSink($name, $call, $context, $taints, $stack);
        }

        if (!isset(self::ARGUMENT_SINKS[$name])) {
            return [];
        }

        return $this->detectArgumentSink($name, self::ARGUMENT_SINKS[$name], (int)$call['line'], $call['args'], $context, $taints, $stack);
    }

    private function detectArgumentSink(string $sink, array $positions, int $line, array $args, AstContext $context, array $taints, array $stack): array
    {
        foreach ($positions as $position) {
            if (empty($args[$position]->value)) {
                continue;
            }

            $trace = $this->propagator->traceForExpression($args[$position]->value, $context, $taints, $stack);

            if ($trace !== null) {
                return [
                    $this->factory->create($trace->withSink($sink, $line, $this->sinkSeverity($sink))),
                ];
            }
        }

        return [];
    }

    private function detectCurlSetopt(array $call, AstContext $context, array $taints, array $stack): array
    {
        if (empty($call['args'][1]->value) || empty($call['args'][2]->value)) {
            return [];
        }

        $option = strtoupper((string)$context->resolveString($call['args'][1]->value));

        if ($option !== 'CURLOPT_URL') {
            return [];
        }

        $trace = $this->propagator->traceForExpression($call['args'][2]->value, $context, $taints, $stack);

        if ($trace === null) {
            return [];
        }

        return [
            $this->factory->create($trace->withSink('curl_setopt_url', (int)$call['line'], Severity::HIGH)),
        ];
    }

    private function detectPregSink(string $name, array $call, AstContext $context, array $taints, array $stack): array
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

                $trace = $this->propagator->traceForExpression($call['args'][$position]->value, $context, $taints, $stack);

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

        $trace = $this->propagator->traceForExpression($call['args'][$callbackPosition]->value, $context, $taints, $stack);

        if ($trace === null) {
            return [];
        }

        return [
            $this->factory->create($trace->withSink($name, (int)$call['line'], Severity::HIGH)),
        ];
    }

    private function detectUserFunctionCall(array $call, AstContext $context, array $taints, array $stack): array
    {
        if (!$call['node'] instanceof Node\Expr\FuncCall) {
            return [];
        }

        $name = isset($call['name']) ? strtolower((string)$call['name']) : '';

        if ($name === '' || empty($context->functions[$name]) || isset($stack[$name])) {
            return [];
        }

        $nextStack = $stack;
        $nextStack[$name] = true;
        $localTaints = $this->propagator->buildForFunctionCall($call['node'], $context, $taints, $stack);
        $findings = [];

        foreach ($context->functions[$name]['stmts'] as $stmt) {
            $findings = array_merge($findings, $this->detectNodeSinks($stmt, $context, $localTaints, $nextStack));
        }

        return $findings;
    }

    private function detectMethodCall(array $call, AstContext $context, array $taints, array $stack): array
    {
        $node = $call['node'];
        $name = isset($call['name']) ? strtolower((string)$call['name']) : '';
        $findings = [];

        if (!$node instanceof Node\Expr\MethodCall) {
            return [];
        }

        if (!$node->name instanceof Node\Identifier) {
            $trace = $node->name instanceof Node ? $this->propagator->traceForExpression($node->name, $context, $taints, $stack) : null;

            if ($trace === null) {
                $trace = $this->traceFirstArgument($call['args'], $context, $taints, $stack);
            }

            if ($trace !== null) {
                $findings[] = $this->factory->create($trace->withSink('dynamic_method_call', (int)$call['line'], Severity::HIGH));
            }

            return $findings;
        }

        if (!isset(self::METHOD_ARGUMENT_SINKS[$name])) {
            return [];
        }

        return $this->detectArgumentSink('method_' . $name, self::METHOD_ARGUMENT_SINKS[$name], (int)$call['line'], $call['args'], $context, $taints, $stack);
    }

    private function detectStaticCall(array $call, AstContext $context, array $taints, array $stack): array
    {
        $node = $call['node'];
        $name = isset($call['name']) ? strtolower((string)$call['name']) : '';

        if (!$node instanceof Node\Expr\StaticCall) {
            return [];
        }

        if (!$node->name instanceof Node\Identifier) {
            $trace = $node->name instanceof Node ? $this->propagator->traceForExpression($node->name, $context, $taints, $stack) : null;

            if ($trace !== null) {
                return [
                    $this->factory->create($trace->withSink('dynamic_static_call', (int)$call['line'], Severity::HIGH)),
                ];
            }

            return [];
        }

        $class = strtolower(trim((string)($call['class'] ?? ''), '\\'));

        if (in_array($class, ['reflectionfunction', 'reflectionmethod'], true) && in_array($name, ['invoke', 'invokeargs'], true)) {
            return $this->detectArgumentSink($class . '_' . $name, [0], (int)$call['line'], $call['args'], $context, $taints, $stack);
        }

        if (!isset(self::STATIC_ARGUMENT_SINKS[$name])) {
            return [];
        }

        return $this->detectArgumentSink('static_' . $name, self::STATIC_ARGUMENT_SINKS[$name], (int)$call['line'], $call['args'], $context, $taints, $stack);
    }

    private function traceDynamicCall(array $call, AstContext $context, array $taints, array $stack = []): ?TaintTrace
    {
        if (!$call['node'] instanceof Node\Expr\FuncCall) {
            return null;
        }

        $trace = $this->propagator->traceForExpression($call['node']->name, $context, $taints, $stack);

        if ($trace !== null) {
            return $trace;
        }

        foreach ($call['args'] as $argument) {
            $trace = $this->propagator->traceForExpression($argument->value, $context, $taints, $stack);

            if ($trace !== null) {
                return $trace;
            }
        }

        return null;
    }

    private function traceFirstArgument(array $args, AstContext $context, array $taints, array $stack): ?TaintTrace
    {
        foreach ($args as $argument) {
            if (empty($argument->value)) {
                continue;
            }

            $trace = $this->propagator->traceForExpression($argument->value, $context, $taints, $stack);

            if ($trace !== null) {
                return $trace;
            }
        }

        return null;
    }

    private function functionCall(Node\Expr\FuncCall $node, AstContext $context): array
    {
        return [
            'node' => $node,
            'name' => $context->resolveString($node->name),
            'line' => $this->line($node),
            'args' => $node->args,
        ];
    }

    private function methodCall(Node\Expr\MethodCall $node, AstContext $context): array
    {
        return [
            'node' => $node,
            'name' => $context->resolveString($node->name),
            'line' => $this->line($node),
            'args' => $node->args,
            'var' => $node->var,
        ];
    }

    private function staticCall(Node\Expr\StaticCall $node, AstContext $context): array
    {
        return [
            'node' => $node,
            'class' => $context->resolveString($node->class),
            'name' => $context->resolveString($node->name),
            'line' => $this->line($node),
            'args' => $node->args,
        ];
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

    private function includeType(Node\Expr\Include_ $node): string
    {
        switch ($node->type) {
            case Node\Expr\Include_::TYPE_INCLUDE_ONCE:
                return 'include_once';
            case Node\Expr\Include_::TYPE_REQUIRE:
                return 'require';
            case Node\Expr\Include_::TYPE_REQUIRE_ONCE:
                return 'require_once';
            case Node\Expr\Include_::TYPE_INCLUDE:
            default:
                return 'include';
        }
    }

    private function line(Node $node): int
    {
        return (int)$node->getStartLine();
    }
}
