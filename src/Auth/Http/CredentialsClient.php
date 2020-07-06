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

declare(strict_types=1);

namespace Google\Auth\Http;

use Google\Http\ClientInterface;
use Google\Http\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class CredentialsClient implements ClientInterface
{
    private $httpClient;
    private $credentials;

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $httpClient = null
    ) {
        $this->credentials = $credentials
        $this->httpClient = $httpClient ?: ClientFactory::build();
    }

    public function sendRequest(
        RequestInterface $request,
        array $options = []
    ): ResponseInterface {
        return $this->httpClient->sendRequest(
            $request->withHeaders($this->credentials->getRequestMetadata()),
            $options
        );
    }

    public function sendRequestAsync(
        RequestInterface $request,
        array $options = []
    ): PromiseInterface {
        return $this->httpClient->sendRequestAsync(
            $request->withHeaders($this->credentials->getRequestMetadata()),
            $options
        );
    }
}
