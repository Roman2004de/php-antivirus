<?php

namespace Delement\Antivirus\Detection\Ast;

class DynamicCallDetector
{
    private const DANGEROUS_DYNAMIC_NAMES = [
        'eval' => true,
        'assert' => true,
        'system' => true,
        'exec' => true,
        'shell_exec' => true,
        'passthru' => true,
        'proc_open' => true,
        'popen' => true,
        'pcntl_exec' => true,
        'create_function' => true,
        'call_user_func' => true,
        'call_user_func_array' => true,
    ];

    private $factory;

    public function __construct(AstFindingFactory $factory = null)
    {
        $this->factory = $factory ?: new AstFindingFactory();
    }

    public function detect(AstContext $context): array
    {
        $findings = [];

        foreach ($context->variableFunctionCalls as $call) {
            $node = $call['node'];

            if ($context->containsSuperglobal($node->name)) {
                $findings[] = $this->factory->superglobalCallable((int)$call['line'], $context->expressionLabel($node->name));
                continue;
            }

            $resolved = $context->resolveString($node->name);
            $score = $resolved !== null && isset(self::DANGEROUS_DYNAMIC_NAMES[strtolower($resolved)]) ? 9 : 7;
            $findings[] = $this->factory->dynamicFunctionCall((int)$call['line'], $context->expressionLabel($node->name), $score);
        }

        foreach ($context->methodCalls as $call) {
            if ($call['node']->name instanceof \PhpParser\Node\Identifier) {
                continue;
            }

            $findings[] = $this->factory->variableMethodCall((int)$call['line'], $context->expressionLabel($call['node']->name));
        }

        foreach ($context->calls as $call) {
            $name = isset($call['name']) ? strtolower((string)$call['name']) : '';

            if (!in_array($name, ['call_user_func', 'call_user_func_array'], true)) {
                continue;
            }

            if (!empty($call['args'][0]->value) && $context->containsSuperglobal($call['args'][0]->value)) {
                $findings[] = $this->factory->superglobalCallable((int)$call['line'], $context->expressionLabel($call['args'][0]->value));
            }
        }

        return $findings;
    }
}
