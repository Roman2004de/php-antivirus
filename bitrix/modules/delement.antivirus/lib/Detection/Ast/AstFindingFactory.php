<?php

namespace Delement\Antivirus\Detection\Ast;

use Delement\Antivirus\Detection\Finding;
use Delement\Antivirus\Detection\Severity;

class AstFindingFactory
{
    public function dangerousCall(string $name, string $severity, int $score, int $line, string $excerpt = ''): Finding
    {
        $name = strtolower($name);

        return $this->create(
            'php_ast_dangerous_call_' . preg_replace('/[^a-z0-9_]+/', '_', $name),
            'PHP AST dangerous call: ' . $name,
            $severity,
            $score,
            $line,
            $excerpt
        );
    }

    public function dynamicFunctionCall(int $line, string $excerpt = '', int $score = 7): Finding
    {
        return $this->create(
            'php_ast_dynamic_function_call',
            'PHP AST dynamic function call',
            Severity::HIGH,
            $score,
            $line,
            $excerpt
        );
    }

    public function variableMethodCall(int $line, string $excerpt = ''): Finding
    {
        return $this->create(
            'php_ast_variable_method_call',
            'PHP AST variable method call',
            Severity::HIGH,
            6,
            $line,
            $excerpt
        );
    }

    public function superglobalCallable(int $line, string $excerpt = ''): Finding
    {
        return $this->create(
            'php_ast_superglobal_callable',
            'PHP AST superglobal callable',
            Severity::CRITICAL,
            9,
            $line,
            $excerpt
        );
    }

    public function encodedExecutionChain(int $line, string $excerpt = ''): Finding
    {
        return $this->create(
            'php_ast_encoded_execution_chain',
            'PHP AST encoded execution chain',
            Severity::CRITICAL,
            10,
            $line,
            $excerpt
        );
    }

    private function create(string $signatureId, string $name, string $severity, int $score, int $line, string $excerpt): Finding
    {
        return new Finding([
            'signature_id' => $signatureId,
            'name' => $name,
            'category' => 'php_ast',
            'severity' => $severity,
            'score' => $score,
            'offset' => $line > 0 ? $line : null,
            'excerpt' => $excerpt,
            'target' => 'ast',
            'rule_type' => 'ast',
        ]);
    }
}
