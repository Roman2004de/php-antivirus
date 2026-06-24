<?php

namespace Delement\Antivirus\Detection\Ast;

class EncodedPayloadDetector
{
    private const DECODERS = [
        'base64_decode',
        'str_rot13',
        'gzinflate',
        'gzuncompress',
        'hex2bin',
        'pack',
    ];

    private const CALLABLE_DECODERS = [
        'unserialize',
    ];

    private const EXECUTION_SINKS = [
        'assert' => true,
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

        foreach ($context->evalNodes as $eval) {
            if ($context->containsFunctionCall($eval['expr'], self::DECODERS)) {
                $findings[] = $this->factory->encodedExecutionChain((int)$eval['line'], 'eval + decoder');
            }
        }

        foreach ($context->calls as $call) {
            $name = isset($call['name']) ? strtolower((string)$call['name']) : '';

            if (!isset(self::EXECUTION_SINKS[$name])) {
                continue;
            }

            foreach ($call['args'] as $argument) {
                if (
                    $context->containsFunctionCall($argument->value, self::DECODERS)
                    || $context->containsFunctionCall($argument->value, self::CALLABLE_DECODERS)
                ) {
                    $findings[] = $this->factory->encodedExecutionChain((int)$call['line'], $name . ' + decoder');
                    break;
                }
            }
        }

        foreach ($context->variableFunctionCalls as $call) {
            foreach ($call['args'] as $argument) {
                if (
                    $context->containsFunctionCall($argument->value, self::DECODERS)
                    || $context->containsFunctionCall($argument->value, self::CALLABLE_DECODERS)
                ) {
                    $findings[] = $this->factory->encodedExecutionChain((int)$call['line'], 'dynamic callable + decoder');
                    break;
                }
            }
        }

        return $findings;
    }
}
