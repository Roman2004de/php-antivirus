<?php

namespace Delement\Antivirus\Detection\Ast;

use PhpParser\Node;

class NodeCollector
{
    public function collect(array $nodes): AstContext
    {
        $context = new AstContext();
        $context->nodes = $nodes;

        foreach ($nodes as $node) {
            $this->walk($node, $context);
        }

        return $context;
    }

    private function walk($node, AstContext $context): void
    {
        if (is_array($node)) {
            foreach ($node as $item) {
                $this->walk($item, $context);
            }

            return;
        }

        if (!$node instanceof Node) {
            return;
        }

        $this->collectNode($node, $context);

        foreach ($node->getSubNodeNames() as $name) {
            $this->walk($node->$name, $context);
        }
    }

    private function collectNode(Node $node, AstContext $context): void
    {
        if ($node instanceof Node\Stmt\Function_) {
            $name = strtolower($node->name->toString());
            $context->functions[$name] = [
                'node' => $node,
                'name' => $name,
                'line' => $this->line($node),
                'params' => $node->params,
                'stmts' => $node->stmts,
            ];
        }

        if ($node instanceof Node\Expr\Assign || $node instanceof Node\Expr\AssignOp) {
            $assignment = [
                'node' => $node,
                'line' => $this->line($node),
                'variable' => $this->variableName($node->var),
                'value' => $node->expr,
            ];
            $context->assignments[] = $assignment;

            if ($assignment['variable'] !== '') {
                $resolved = $context->resolveString($node->expr);

                if ($resolved !== null) {
                    $context->assignmentValues[$assignment['variable']] = $resolved;
                }
            }
        }

        if ($node instanceof Node\Expr\FuncCall) {
            $call = [
                'node' => $node,
                'name' => $context->resolveString($node->name),
                'line' => $this->line($node),
                'args' => $node->args,
            ];
            $context->calls[] = $call;

            if (!$node->name instanceof Node\Name) {
                $context->variableFunctionCalls[] = $call;
                $context->dynamicCalls[] = $call;
            }
        }

        if ($node instanceof Node\Expr\MethodCall) {
            $call = [
                'node' => $node,
                'name' => $context->resolveString($node->name),
                'line' => $this->line($node),
                'args' => $node->args,
                'var' => $node->var,
            ];
            $context->methodCalls[] = $call;

            if (!$node->name instanceof Node\Identifier) {
                $context->dynamicCalls[] = $call;
            }
        }

        if ($node instanceof Node\Expr\StaticCall) {
            $context->staticCalls[] = [
                'node' => $node,
                'class' => $context->resolveString($node->class),
                'name' => $context->resolveString($node->name),
                'line' => $this->line($node),
                'args' => $node->args,
            ];
        }

        if ($node instanceof Node\Expr\Eval_) {
            $context->evalNodes[] = [
                'node' => $node,
                'line' => $this->line($node),
                'expr' => $node->expr,
            ];
        }

        if ($node instanceof Node\Expr\Include_) {
            $context->includes[] = [
                'node' => $node,
                'line' => $this->line($node),
                'type' => $this->includeType($node),
                'expr' => $node->expr,
            ];
        }

        if ($node instanceof Node\Scalar\String_ && $node->value !== '') {
            $context->strings[] = [
                'node' => $node,
                'line' => $this->line($node),
                'value' => $node->value,
            ];
        }

        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            $context->concatExpressions[] = [
                'node' => $node,
                'line' => $this->line($node),
                'value' => $context->resolveString($node),
            ];
        }

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            $context->arrayAccess[] = [
                'node' => $node,
                'line' => $this->line($node),
                'var' => $node->var,
                'dim' => $node->dim,
            ];
        }

        if ($node instanceof Node\Stmt\Foreach_) {
            $context->foreachNodes[] = [
                'node' => $node,
                'line' => $this->line($node),
                'expr' => $node->expr,
                'key_var' => $node->keyVar,
                'value_var' => $node->valueVar,
            ];
        }

        if ($node instanceof Node\Stmt\Return_) {
            $context->returns[] = [
                'node' => $node,
                'line' => $this->line($node),
                'expr' => $node->expr,
            ];
        }

        if ($node instanceof Node\Expr\Variable && is_string($node->name) && $this->isSuperglobal($node->name)) {
            $context->superglobals[] = [
                'node' => $node,
                'line' => $this->line($node),
                'name' => $node->name,
            ];
        }
    }

    private function variableName($node): string
    {
        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            return $node->name;
        }

        return '';
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

    private function isSuperglobal(string $name): bool
    {
        return in_array($name, ['_GET', '_POST', '_REQUEST', '_COOKIE', '_FILES', '_SERVER', 'GLOBALS'], true);
    }

    private function line(Node $node): int
    {
        return (int)$node->getStartLine();
    }
}
