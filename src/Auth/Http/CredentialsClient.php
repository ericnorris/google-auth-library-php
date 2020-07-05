<?php

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
