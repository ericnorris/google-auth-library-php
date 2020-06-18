<?php

namespace Google\Http;

/**
 * A+ Promise implementation
 *
 * @link https://promisesaplus.com/
 */
interface PromisorInterface
{
    /**
     * Returns a promise.
     *
     * @return PromiseInterface
     */
    public function promise();
}
