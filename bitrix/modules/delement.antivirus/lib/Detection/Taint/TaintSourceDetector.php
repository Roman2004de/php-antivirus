<?php

namespace Delement\Antivirus\Detection\Taint;

use Delement\Antivirus\Detection\Ast\AstContext;
use PhpParser\Node;

class TaintSourceDetector
{
    private const SUPERGLOBALS = [
        '_GET' => true,
        '_POST' => true,
        '_REQUEST' => true,
        '_COOKIE' => true,
        '_FILES' => true,
    ];

    public function detect($node, AstContext $context): ?TaintTrace
    {
        if (!$node instanceof Node) {
            return null;
        }

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            return $this->detectArraySource($node, $context);
        }

        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            if (isset(self::SUPERGLOBALS[$node->name])) {
                return TaintTrace::source('$' . $node->name, $this->line($node));
            }

            if ($node->name === '_SERVER') {
                return TaintTrace::source('$_SERVER', $this->line($node));
            }
        }

        if ($node instanceof Node\Expr\FuncCall) {
            return $this->detectFunctionSource($node, $context);
        }

        return null;
    }

    private function detectArraySource(Node\Expr\ArrayDimFetch $node, AstContext $context): ?TaintTrace
    {
        if (!$node->var instanceof Node\Expr\Variable || !is_string($node->var->name)) {
            return null;
        }

        $name = $node->var->name;

        if (isset(self::SUPERGLOBALS[$name])) {
            return TaintTrace::source($this->sourceLabel($name, $node->dim, $context), $this->line($node));
        }

        if ($name !== '_SERVER') {
            return null;
        }

        $dim = $context->resolveString($node->dim);

        if (strtoupper((string)$dim) === 'DOCUMENT_ROOT') {
            return null;
        }

        return TaintTrace::source($this->sourceLabel($name, $node->dim, $context), $this->line($node));
    }

    private function detectFunctionSource(Node\Expr\FuncCall $node, AstContext $context): ?TaintTrace
    {
        $name = $context->resolveString($node->name);
        $name = $name !== null ? strtolower($name) : '';

        if ($name === 'filter_input') {
            return TaintTrace::source('filter_input()', $this->line($node));
        }

        if ($name !== 'file_get_contents' || empty($node->args[0]->value)) {
            return null;
        }

        $path = $context->resolveString($node->args[0]->value);

        if ($path !== null && strtolower($path) === 'php://input') {
            return TaintTrace::source('php://input', $this->line($node));
        }

        return null;
    }

    private function sourceLabel(string $name, $dim, AstContext $context): string
    {
        $label = '$' . $name;
        $key = $context->resolveString($dim);

        if ($key !== null && $key !== '') {
            return $label . '[' . var_export($key, true) . ']';
        }

        return $label . '[...]';
    }

    private function line(Node $node): int
    {
        return (int)$node->getStartLine();
    }
}
