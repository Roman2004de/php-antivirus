<?php

namespace Delement\Antivirus\Detection\Ast;

class AstParseResult
{
    private $success;
    private $nodes;
    private $error;

    private function __construct(bool $success, array $nodes = [], string $error = '')
    {
        $this->success = $success;
        $this->nodes = $nodes;
        $this->error = $error;
    }

    public static function success(array $nodes): self
    {
        return new self(true, $nodes, '');
    }

    public static function failure(string $error): self
    {
        return new self(false, [], $error);
    }

    public function isSuccess(): bool
    {
        return $this->success;
    }

    public function getNodes(): array
    {
        return $this->nodes;
    }

    public function getError(): string
    {
        return $this->error;
    }
}
