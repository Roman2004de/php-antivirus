<?php

namespace Delement\Antivirus\Detection\Ast;

use PhpParser\Node;

class AstContext
{
    public $calls = [];
    public $assignments = [];
    public $dangerousCalls = [];
    public $dynamicCalls = [];
    public $includes = [];
    public $superglobals = [];
    public $strings = [];
    public $methodCalls = [];
    public $staticCalls = [];
    public $evalNodes = [];
    public $concatExpressions = [];
    public $arrayAccess = [];
    public $variableFunctionCalls = [];
    public $assignmentValues = [];

    private const SUPERGLOBALS = [
        '_GET' => true,
        '_POST' => true,
        '_REQUEST' => true,
        '_COOKIE' => true,
        '_FILES' => true,
        '_SERVER' => true,
        'GLOBALS' => true,
    ];

    public function resolveString($node, int $depth = 0): ?string
    {
        if ($depth > 8 || !$node instanceof Node) {
            return null;
        }

        if ($node instanceof Node\Scalar\String_) {
            return $node->value;
        }

        if ($node instanceof Node\Scalar\LNumber || $node instanceof Node\Scalar\DNumber) {
            return (string)$node->value;
        }

        if ($node instanceof Node\Name) {
            return $node->toString();
        }

        if ($node instanceof Node\Identifier) {
            return $node->toString();
        }

        if ($node instanceof Node\Expr\ConstFetch) {
            return $node->name->toString();
        }

        if ($node instanceof Node\Expr\BinaryOp\Concat) {
            $left = $this->resolveString($node->left, $depth + 1);
            $right = $this->resolveString($node->right, $depth + 1);

            return $left !== null && $right !== null ? $left . $right : null;
        }

        if ($node instanceof Node\Expr\Variable && is_string($node->name)) {
            return isset($this->assignmentValues[$node->name]) ? $this->assignmentValues[$node->name] : null;
        }

        if ($node instanceof Node\Scalar\Encapsed) {
            $value = '';

            foreach ($node->parts as $part) {
                if ($part instanceof Node\Scalar\EncapsedStringPart) {
                    $value .= $part->value;
                    continue;
                }

                $partValue = $this->resolveString($part, $depth + 1);

                if ($partValue === null) {
                    return null;
                }

                $value .= $partValue;
            }

            return $value;
        }

        return null;
    }

    public function containsSuperglobal($node): bool
    {
        if (!$node instanceof Node) {
            return false;
        }

        if ($node instanceof Node\Expr\Variable && is_string($node->name) && isset(self::SUPERGLOBALS[$node->name])) {
            return true;
        }

        foreach ($node->getSubNodeNames() as $name) {
            $value = $node->$name;

            if (is_array($value)) {
                foreach ($value as $item) {
                    if ($this->containsSuperglobal($item)) {
                        return true;
                    }
                }
                continue;
            }

            if ($this->containsSuperglobal($value)) {
                return true;
            }
        }

        return false;
    }

    public function containsFunctionCall($node, array $names): bool
    {
        if (!$node instanceof Node) {
            return false;
        }

        $lookup = [];

        foreach ($names as $name) {
            $lookup[strtolower((string)$name)] = true;
        }

        return $this->containsFunctionCallLookup($node, $lookup);
    }

    public function expressionLabel($node): string
    {
        if (!$node instanceof Node) {
            return '';
        }

        if ($node instanceof Node\Expr\Variable) {
            return is_string($node->name) ? '$' . $node->name : '${...}';
        }

        if ($node instanceof Node\Expr\ArrayDimFetch) {
            return $this->expressionLabel($node->var) . '[...]';
        }

        if ($node instanceof Node\Expr\PropertyFetch) {
            return $this->expressionLabel($node->var) . '->...';
        }

        if ($node instanceof Node\Expr\ConstFetch) {
            return $node->name->toString();
        }

        $resolved = $this->resolveString($node);

        if ($resolved !== null) {
            return $resolved;
        }

        $classParts = explode('\\', get_class($node));

        return end($classParts) ?: 'node';
    }

    private function containsFunctionCallLookup(Node $node, array $lookup): bool
    {
        if ($node instanceof Node\Expr\FuncCall) {
            $name = $this->resolveString($node->name);

            if ($name !== null && isset($lookup[strtolower($name)])) {
                return true;
            }
        }

        foreach ($node->getSubNodeNames() as $name) {
            $value = $node->$name;

            if (is_array($value)) {
                foreach ($value as $item) {
                    if ($item instanceof Node && $this->containsFunctionCallLookup($item, $lookup)) {
                        return true;
                    }
                }
                continue;
            }

            if ($value instanceof Node && $this->containsFunctionCallLookup($value, $lookup)) {
                return true;
            }
        }

        return false;
    }
}
