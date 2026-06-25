<?php

namespace Delement\Antivirus\Detection\Taint;

use Delement\Antivirus\Detection\Ast\AstContext;
use PhpParser\Node;

class TaintPropagator
{
    private const MAX_PASSES = 5;

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

    private const SANITIZING_FUNCTIONS = [
        'abs' => true,
        'boolval' => true,
        'floatval' => true,
        'intval' => true,
    ];

    private $sourceDetector;

    public function __construct(TaintSourceDetector $sourceDetector = null)
    {
        $this->sourceDetector = $sourceDetector ?: new TaintSourceDetector();
    }

    public function build(AstContext $context): array
    {
        return $this->propagateNodes($context->nodes, $context, []);
    }

    public function buildForFunctionCall(Node\Expr\FuncCall $call, AstContext $context, array $taints, array $stack = []): array
    {
        $function = $this->functionDefinition($call, $context);

        if ($function === null) {
            return [];
        }

        $name = (string)$function['name'];

        if (isset($stack[$name])) {
            return [];
        }

        $localTaints = [];

        foreach ($function['params'] as $index => $param) {
            if (!$param instanceof Node\Param || !$param->var instanceof Node\Expr\Variable || !is_string($param->var->name)) {
                continue;
            }

            if (empty($call->args[$index]->value)) {
                continue;
            }

            $trace = $this->traceForExpression($call->args[$index]->value, $context, $taints, $stack);

            if ($trace === null) {
                continue;
            }

            $localTaints[$param->var->name] = $trace->withTransform('param:' . $param->var->name, $this->line($call));
        }

        $nextStack = $stack;
        $nextStack[$name] = true;

        return $this->propagateNodes($function['stmts'], $context, $localTaints, $nextStack);
    }

    public function propagateNodes(array $nodes, AstContext $context, array $taints, array $stack = []): array
    {
        for ($pass = 0; $pass < self::MAX_PASSES; $pass++) {
            $changed = false;

            foreach ($nodes as $node) {
                $changed = $this->propagateNode($node, $context, $taints, $stack) || $changed;
            }

            if (!$changed) {
                break;
            }
        }

        return $taints;
    }

    public function traceForExpression($node, AstContext $context, array $taints, array $stack = []): ?TaintTrace
    {
        if (!$node instanceof Node) {
            return null;
        }

        if ($this->isSanitizingExpression($node, $context)) {
            return null;
        }

        $sourceTrace = $this->sourceDetector->detect($node, $context);

        if ($sourceTrace !== null) {
            return $sourceTrace;
        }

        foreach ($this->expressionKeys($node, $context) as $key) {
            if (isset($taints[$key])) {
                return $taints[$key];
            }
        }

        if ($node instanceof Node\Expr\Array_) {
            foreach ($node->items as $item) {
                if ($item === null) {
                    continue;
                }

                $trace = $this->traceForExpression($item->value, $context, $taints, $stack);

                if ($trace !== null) {
                    return $trace->withTransform('array', $this->line($node));
                }

                if ($item->key instanceof Node) {
                    $trace = $this->traceForExpression($item->key, $context, $taints, $stack);

                    if ($trace !== null) {
                        return $trace->withTransform('array_key', $this->line($node));
                    }
                }
            }
        }

        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            $leftTrace = $this->traceForExpression($node->left, $context, $taints, $stack);

            if ($leftTrace !== null) {
                return $leftTrace->withTransform('concat', $this->line($node));
            }

            $rightTrace = $this->traceForExpression($node->right, $context, $taints, $stack);

            return $rightTrace !== null ? $rightTrace->withTransform('concat', $this->line($node)) : null;
        }

        if ($node instanceof Node\Expr\Ternary) {
            $ifTrace = $node->if instanceof Node ? $this->traceForExpression($node->if, $context, $taints, $stack) : null;

            if ($ifTrace !== null) {
                return $ifTrace;
            }

            return $this->traceForExpression($node->else, $context, $taints, $stack);
        }

        if ($node instanceof Node\Expr\BinaryOp\Coalesce) {
            $leftTrace = $this->traceForExpression($node->left, $context, $taints, $stack);

            return $leftTrace !== null ? $leftTrace : $this->traceForExpression($node->right, $context, $taints, $stack);
        }

        if ($node instanceof Node\Expr\FuncCall) {
            $name = $this->callName($node, $context);

            if ($name !== '' && isset(self::PRESERVING_FUNCTIONS[$name])) {
                $trace = $this->traceFirstArgument($node->args, $context, $taints, $stack);

                return $trace !== null ? $trace->withTransform($name, $this->line($node)) : null;
            }

            $trace = $this->traceUserFunctionReturn($node, $context, $taints, $stack);

            if ($trace !== null) {
                return $trace;
            }

            return $this->traceFirstArgument($node->args, $context, $taints, $stack);
        }

        if ($node instanceof Node\Expr\MethodCall || $node instanceof Node\Expr\StaticCall) {
            return $this->traceFirstArgument($node->args, $context, $taints, $stack);
        }

        return null;
    }

    private function propagateNode($node, AstContext $context, array &$taints, array $stack): bool
    {
        if (is_array($node)) {
            $changed = false;

            foreach ($node as $item) {
                $changed = $this->propagateNode($item, $context, $taints, $stack) || $changed;
            }

            return $changed;
        }

        if (!$node instanceof Node) {
            return false;
        }

        if (
            $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Expr\Closure
            || $node instanceof Node\Stmt\Class_
            || $node instanceof Node\Stmt\ClassMethod
            || $node instanceof Node\Stmt\Trait_
            || $node instanceof Node\Stmt\Interface_
        ) {
            return false;
        }

        $changed = false;

        if ($node instanceof Node\Expr\Assign || $node instanceof Node\Expr\AssignOp) {
            $trace = $this->traceForExpression($node->expr, $context, $taints, $stack);

            if ($trace !== null) {
                foreach ($this->assignmentKeys($node->var, $context) as $key) {
                    $changed = $this->addTaint($taints, $key, $trace) || $changed;
                }
            }
        }

        if ($node instanceof Node\Stmt\Foreach_) {
            $trace = $this->traceForExpression($node->expr, $context, $taints, $stack);

            if ($trace !== null) {
                foreach ($this->assignmentKeys($node->valueVar, $context) as $key) {
                    $changed = $this->addTaint($taints, $key, $trace->withTransform('foreach_value', $this->line($node))) || $changed;
                }

                if ($node->keyVar instanceof Node) {
                    foreach ($this->assignmentKeys($node->keyVar, $context) as $key) {
                        $changed = $this->addTaint($taints, $key, $trace->withTransform('foreach_key', $this->line($node))) || $changed;
                    }
                }
            }
        }

        foreach ($node->getSubNodeNames() as $name) {
            $changed = $this->propagateNode($node->$name, $context, $taints, $stack) || $changed;
        }

        return $changed;
    }

    private function traceFirstArgument(array $args, AstContext $context, array $taints, array $stack): ?TaintTrace
    {
        foreach ($args as $argument) {
            if (empty($argument->value)) {
                continue;
            }

            $trace = $this->traceForExpression($argument->value, $context, $taints, $stack);

            if ($trace !== null) {
                return $trace;
            }
        }

        return null;
    }

    private function traceUserFunctionReturn(Node\Expr\FuncCall $call, AstContext $context, array $taints, array $stack): ?TaintTrace
    {
        $function = $this->functionDefinition($call, $context);

        if ($function === null) {
            return null;
        }

        $name = (string)$function['name'];

        if (isset($stack[$name])) {
            return null;
        }

        $nextStack = $stack;
        $nextStack[$name] = true;
        $localTaints = $this->buildForFunctionCall($call, $context, $taints, $stack);

        foreach ($this->returnNodes($function['stmts']) as $returnNode) {
            if (!$returnNode->expr instanceof Node) {
                continue;
            }

            $trace = $this->traceForExpression($returnNode->expr, $context, $localTaints, $nextStack);

            if ($trace !== null) {
                return $trace->withTransform('return:' . $name, $this->line($returnNode));
            }
        }

        return null;
    }

    private function returnNodes(array $nodes): array
    {
        $returns = [];

        foreach ($nodes as $node) {
            $this->collectReturnNodes($node, $returns);
        }

        return $returns;
    }

    private function collectReturnNodes($node, array &$returns): void
    {
        if (is_array($node)) {
            foreach ($node as $item) {
                $this->collectReturnNodes($item, $returns);
            }

            return;
        }

        if (!$node instanceof Node) {
            return;
        }

        if (
            $node instanceof Node\Stmt\Function_
            || $node instanceof Node\Expr\Closure
            || $node instanceof Node\Stmt\Class_
            || $node instanceof Node\Stmt\ClassMethod
            || $node instanceof Node\Stmt\Trait_
            || $node instanceof Node\Stmt\Interface_
        ) {
            return;
        }

        if ($node instanceof Node\Stmt\Return_) {
            $returns[] = $node;
            return;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $this->collectReturnNodes($node->$name, $returns);
        }
    }

    private function assignmentKeys($node, AstContext $context): array
    {
        $keys = $this->expressionKeys($node, $context);

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            foreach ($this->expressionKeys($node->var, $context) as $baseKey) {
                $keys[] = $baseKey;
            }
        }

        return array_values(array_unique(array_filter($keys, 'strlen')));
    }

    private function expressionKeys($node, AstContext $context): array
    {
        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            return [$node->name];
        }

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            $keys = [];
            $dim = $node->dim instanceof Node ? $context->resolveString($node->dim) : null;

            foreach ($this->expressionKeys($node->var, $context) as $baseKey) {
                if ($dim !== null && $dim !== '') {
                    $keys[] = $baseKey . '[' . $dim . ']';
                }

                $keys[] = $baseKey . '[]';
                $keys[] = $baseKey;
            }

            return array_values(array_unique($keys));
        }

        if ($node instanceof Node\Expr\PropertyFetch) {
            $keys = [];
            $property = $node->name instanceof Node ? $context->resolveString($node->name) : null;

            foreach ($this->expressionKeys($node->var, $context) as $baseKey) {
                $keys[] = $property !== null && $property !== '' ? $baseKey . '->' . $property : $baseKey . '->*';
            }

            return array_values(array_unique($keys));
        }

        return [];
    }

    private function addTaint(array &$taints, string $key, TaintTrace $trace): bool
    {
        if ($key === '') {
            return false;
        }

        $fingerprint = json_encode($trace->toArray());

        if (isset($taints[$key]) && json_encode($taints[$key]->toArray()) === $fingerprint) {
            return false;
        }

        $taints[$key] = $trace;

        return true;
    }

    private function functionDefinition(Node\Expr\FuncCall $call, AstContext $context): ?array
    {
        $name = $this->callName($call, $context);

        if ($name === '' || empty($context->functions[$name])) {
            return null;
        }

        return $context->functions[$name];
    }

    private function callName(Node\Expr\FuncCall $call, AstContext $context): string
    {
        $name = $context->resolveString($call->name);

        return $name !== null ? strtolower($name) : '';
    }

    private function isSanitizingExpression(Node $node, AstContext $context): bool
    {
        if (
            $node instanceof Node\Expr\Cast\Int_
            || $node instanceof Node\Expr\Cast\Double
            || $node instanceof Node\Expr\Cast\Bool_
        ) {
            return true;
        }

        if (!$node instanceof Node\Expr\FuncCall) {
            return false;
        }

        $name = $this->callName($node, $context);

        if (isset(self::SANITIZING_FUNCTIONS[$name])) {
            return true;
        }

        if ($name !== 'filter_var' || empty($node->args[1]->value)) {
            return false;
        }

        $filter = strtoupper((string)$context->resolveString($node->args[1]->value));

        return strpos($filter, 'FILTER_VALIDATE_') === 0
            || in_array($filter, ['FILTER_SANITIZE_NUMBER_INT', 'FILTER_SANITIZE_NUMBER_FLOAT'], true);
    }

    private function line(Node $node): int
    {
        return (int)$node->getStartLine();
    }
}
