<?php

namespace Delement\Antivirus\Detection\Entropy;

class EntropyCalculator
{
    public function shannon(string $value): float
    {
        $length = strlen($value);

        if ($length === 0) {
            return 0.0;
        }

        $frequencies = [];

        for ($index = 0; $index < $length; $index++) {
            $byte = ord($value[$index]);
            $frequencies[$byte] = isset($frequencies[$byte]) ? $frequencies[$byte] + 1 : 1;
        }

        $entropy = 0.0;

        foreach ($frequencies as $count) {
            $probability = $count / $length;
            $entropy -= $probability * log($probability, 2);
        }

        return $entropy;
    }
}
