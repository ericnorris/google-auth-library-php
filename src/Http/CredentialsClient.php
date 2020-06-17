<?php

namespace Google\Auth\Http;

use Google\Http\ClientInterface;
use Google\Http\PromiseInterface;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class CredentialsClient implements ClientInterface
{
    private $http;
    private $credentials;

    public function __construct(
        CredentialsInterface $credentials,
        ClientInterface $http = null
    ) {
        $this->credentials = $credentials
        $this->http = $http ?: ClientFactory::build();
    }

    public function sendRequest(
        RequestInterface $request,
        array $options = []
    ): ResponseInterface {
        return $this->http->sendRequest(
            $request->withHeaders($this->credentials->getRequestMetadata()),
            $options
        );
    }

    public function sendRequestAsync(
        RequestInterface $request,
        array $options = []
    ): PromiseInterface {
        return $this->http->sendRequestAsync(
            $request->withHeaders($this->credentials->getRequestMetadata()),
            $options
        );
    }
}
