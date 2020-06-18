<?php

namespace Google\Auth\Http;

use Google\Http\ClientInterface;
use Google\Http\PromiseInterface;
use GuzzleHttp\Psr7;
use Psr\Http\Message\RequestInterface;
use Psr\Http\Message\ResponseInterface;

class ApiKeyClient implements ClientInterface
{
    private $http;
    private $apiKey;

    public function __construct(
        string $apiKey,
        ClientInterface $http = null
    ) {
        $this->apiKey = $apiKey
        $this->http = $http ?: ClientFactory::build();
    }

    public function send(
        RequestInterface $request,
        array $options = []
    ) {
        return $this->http->send(
            $this->applyApiKey($request)
            $options
        );
    }

    public function sendAsync(
        RequestInterface $request,
        array $options = []
    ) {
        return $this->http->sendRequestAsync(
            $this->applyApiKey($request)
            $options
        );
    }

    private function applyApiKey(RequestInterface $request): RequestInterface
    {
        $query = Psr7\parse_query($request->getUri()->getQuery());
        $query['key'] = $this->apiKey;
        $uri = $request->getUri()->withQuery(Psr7\build_query($params));
        return $request->withUri($uri);
    }
}
