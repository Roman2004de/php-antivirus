<?php

namespace Delement\Antivirus\Detection\Taint;

use Delement\Antivirus\Detection\Ast\AstContext;
use PhpParser\Node;

class TaintPropagator
{
    private const PRESERVING_FUNCTIONS = [
        'base64_decode' => true,
        'str_rot13' => true,
        'urldecode' => true,
        'rawurldecode' => true,
        'gzinflate' => true,
        'gzuncompress' => true,
        'hex2bin' => true,
        'str_replace' => true,
        'preg_replace' => true,
        'substr' => true,
        'trim' => true,
        'implode' => true,
        'join' => true,
        'json_decode' => true,
        'unserialize' => true,
    ];

    private $sourceDetector;

    public function __construct(TaintSourceDetector $sourceDetector = null)
    {
        $this->sourceDetector = $sourceDetector ?: new TaintSourceDetector();
    }

    public function build(AstContext $context): array
    {
        $taints = [];

        foreach ($context->assignments as $assignment) {
            if (empty($assignment['node']) || !$assignment['node'] instanceof Node) {
                continue;
            }

            $trace = $this->traceForExpression($assignment['value'], $context, $taints);

            if ($trace === null) {
                continue;
            }

            foreach ($this->assignmentKeys($assignment['node']->var) as $key) {
                $taints[$key] = $trace;
            }
        }

        return $taints;
    }

    public function traceForExpression($node, AstContext $context, array $taints): ?TaintTrace
    {
        if (!$node instanceof Node) {
            return null;
        }

        $sourceTrace = $this->sourceDetector->detect($node, $context);

        if ($sourceTrace !== null) {
            return $sourceTrace;
        }

        foreach ($this->expressionKeys($node) as $key) {
            if (isset($taints[$key])) {
                return $taints[$key];
            }
        }

        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            $leftTrace = $this->traceForExpression($node->left, $context, $taints);

            if ($leftTrace !== null) {
                return $leftTrace->withTransform('concat', $this->line($node));
            }

            $rightTrace = $this->traceForExpression($node->right, $context, $taints);

            return $rightTrace !== null ? $rightTrace->withTransform('concat', $this->line($node)) : null;
        }

        if ($node instanceof Node\Expr\FuncCall) {
            $name = $context->resolveString($node->name);
            $name = $name !== null ? strtolower($name) : '';

            foreach ($node->args as $argument) {
                $trace = $this->traceForExpression($argument->value, $context, $taints);

                if ($trace === null) {
                    continue;
                }

                return isset(self::PRESERVING_FUNCTIONS[$name])
                    ? $trace->withTransform($name, $this->line($node))
                    : $trace;
            }
        }

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            foreach ($this->expressionKeys($node->var) as $key) {
                if (isset($taints[$key])) {
                    return $taints[$key];
                }
            }
        }

        return null;
    }

    private function assignmentKeys($node): array
    {
        $keys = $this->expressionKeys($node);

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            foreach ($this->expressionKeys($node->var) as $baseKey) {
                $keys[] = $baseKey;
            }
        }

        return array_values(array_unique($keys));
    }

    private function expressionKeys($node): array
    {
        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            return [$node->name];
        }

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            $keys = [];

            foreach ($this->expressionKeys($node->var) as $baseKey) {
                $keys[] = $baseKey . '[]';
            }

            return $keys;
        }

        return [];
    }

    private function line(Node $node): int
    {
        return (int)$node->getStartLine();
    }
}
