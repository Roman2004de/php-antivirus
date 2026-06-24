<?php

namespace Delement\Antivirus\Detection\Taint;

class TaintTrace
{
    private const SOURCE_RISK = 3;
    private const TRANSFORM_RISK = 2;
    private const SINK_RISK = 5;
    private const CONTEXT_BONUS = 2;

    private $source;
    private $sourceLine;
    private $transforms;
    private $sink;
    private $sinkLine;
    private $sinkSeverity;

    private function __construct(string $source, int $sourceLine = 0, array $transforms = [], string $sink = '', int $sinkLine = 0, string $sinkSeverity = 'critical')
    {
        $this->source = $source;
        $this->sourceLine = $sourceLine;
        $this->transforms = $transforms;
        $this->sink = $sink;
        $this->sinkLine = $sinkLine;
        $this->sinkSeverity = $sinkSeverity;
    }

    public static function source(string $source, int $line = 0): self
    {
        return new self($source, $line);
    }

    public function withTransform(string $transform, int $line = 0): self
    {
        $copy = clone $this;
        $copy->transforms[] = [
            'name' => $transform,
            'line' => $line,
        ];

        return $copy;
    }

    public function withSink(string $sink, int $line = 0, string $severity = 'critical'): self
    {
        $copy = clone $this;
        $copy->sink = $sink;
        $copy->sinkLine = $line;
        $copy->sinkSeverity = $severity;

        return $copy;
    }

    public function getSource(): string
    {
        return $this->source;
    }

    public function getSink(): string
    {
        return $this->sink;
    }

    public function getSeverity(): string
    {
        return $this->sinkSeverity;
    }

    public function getScore(): int
    {
        return min(10, $this->getRawScore());
    }

    public function getRawScore(): int
    {
        return self::SOURCE_RISK
            + (!empty($this->transforms) ? self::TRANSFORM_RISK : 0)
            + self::SINK_RISK
            + self::CONTEXT_BONUS;
    }

    public function toArray(): array
    {
        return [
            'source' => $this->source,
            'source_line' => $this->sourceLine,
            'transforms' => $this->transforms,
            'sink' => $this->sink,
            'sink_line' => $this->sinkLine,
            'risk' => [
                'source' => self::SOURCE_RISK,
                'transform' => !empty($this->transforms) ? self::TRANSFORM_RISK : 0,
                'sink' => self::SINK_RISK,
                'context_bonus' => self::CONTEXT_BONUS,
                'raw_score' => $this->getRawScore(),
                'score' => $this->getScore(),
            ],
        ];
    }

    public function toExcerpt(): string
    {
        $parts = ['source: ' . $this->source];

        foreach ($this->transforms as $transform) {
            $parts[] = 'transform: ' . (string)$transform['name'];
        }

        if ($this->sink !== '') {
            $parts[] = 'sink: ' . $this->sink;
        }

        return implode(' -> ', $parts);
    }
}
