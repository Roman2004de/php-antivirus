<?php

namespace Delement\Antivirus\Detection\Ast;

use PhpParser\Error;
use PhpParser\ParserFactory;
use Throwable;

class PhpAstParser
{
    private $moduleRoot;
    private $parser;

    public function __construct(string $moduleRoot = null)
    {
        $this->moduleRoot = $moduleRoot !== null ? rtrim($moduleRoot, '/\\') : dirname(__DIR__, 3);
    }

    public function parse(string $code): AstParseResult
    {
        if (!$this->ensureParser()) {
            return AstParseResult::failure('php_parser_not_available');
        }

        $source = $this->hasPhpOpenTag($code) ? $code : "<?php\n" . $code;

        try {
            $nodes = $this->parser->parse($source);

            return AstParseResult::success(is_array($nodes) ? $nodes : []);
        } catch (Error $exception) {
            return AstParseResult::failure($exception->getMessage());
        } catch (Throwable $exception) {
            return AstParseResult::failure('php_ast_parse_failed');
        }
    }

    private function ensureParser(): bool
    {
        if ($this->parser !== null) {
            return true;
        }

        if (!class_exists(ParserFactory::class)) {
            $autoload = $this->moduleRoot . '/vendor/autoload.php';

            if (is_file($autoload)) {
                require_once $autoload;
            }
        }

        if (!class_exists(ParserFactory::class)) {
            return false;
        }

        $this->parser = (new ParserFactory())->create(ParserFactory::PREFER_PHP7);

        return true;
    }

    private function hasPhpOpenTag(string $code): bool
    {
        return preg_match('/^\s*<\?(php|=)?/i', $code) === 1;
    }
}
