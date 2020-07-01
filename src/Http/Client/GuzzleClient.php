<?php
/*
 * Copyright 2020 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

namespace Google\Http\Client;

use Google\Http\ClientInterface;
use Google\Http\Promise\GuzzlePromise;
use Google\Http\Promise\PromiseInterface;
use GuzzleHttp\ClientInterface as GuzzleClientInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class GuzzleClient implements ClientInterface
{
    /**
     * @var \GuzzleHttp\ClientInterface
     */
    private $client;

    /**
     * @param \GuzzleHttp\ClientInterface $client
     */
    public function __construct(GuzzleClientInterface $client)
    {
        $this->client = $client;
    }

    /**
     * Accepts a PSR-7 request and an array of options and returns a PSR-7 response.
     *
     * @param RequestInterface $request
     * @param array $options
     *
     * @return \Psr\Http\Message\ResponseInterface
     */
    public function send(RequestInterface $request, array $options = [])
    {
        return $this->client->send($request, $options);
    }

    /**
     * Accepts a PSR-7 request and an array of options and returns a PromiseInterface
     *
     * @param \Psr\Http\Message\RequestInterface $request
     * @param array $options
     *
     * @return \Google\Http\Promise\PromiseInterface
     * @throws \LogicException
     */
    public function sendAsync(RequestInterface $request, array $options = []): PromiseInterface
    {
        return new GuzzlePromise($this->client->sendAsync($request, $options));
    }

    private function getGuzzleMajorVersion(): int
    {
        if (defined('GuzzleHttp\ClientInterface::VERSION')) {
            // Guzzle 4 (unsupported), 5 (unsupported), and 6
            return ClientInterface::VERSION[0];
        }
        if (defined('GuzzleHttp\ClientInterface::MAJOR_VERSION')) {
            // Guzzle 7
            return ClientInterface::MAJOR_VERSION;
        }
        throw new \LogicException('Unable to detect Guzzle version');
    }
}