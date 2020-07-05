<?php
/*
 * Copyright 2015 Google Inc.
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

namespace Google\Auth\Credentials;

use Google\Auth\GetQuotaProjectInterface;
use Google\Auth\Http\ClientFactory;
use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use Google\Auth\ProjectIdProviderInterface;
use Google\Auth\SignBlob\SignBlobInterface;
use Google\Auth\SignBlob\ServiceAccountApiSignBlobTrait;
use GuzzleHttp\Exception\ClientException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ServerException;
use GuzzleHttp\Psr7\Request;
use InvalidArgumentException;

/**
 * ComputeCredentials supports authorization on Google Compute Engine.
 *
 * It can be used to authorize requests using the AuthTokenMiddleware, but will
 * only succeed if being run on GCE:
 *
 *   use Google\Auth\Credentials\ComputeCredentials;
 *   use Google\Auth\Http\CredentialsClient;
 *   use Psr\Http\Message\Request;
 *
 *   $gce = new ComputeCredentials();
 *   $http = new CredentialsClient($gce);
 *
 *   $url = 'https://www.googleapis.com/taskqueue/v1beta2/projects';
 *   $res = $http->send(new Request('GET', $url));
 */
class ComputeCredentials implements
    CredentialsInterface,
    SignBlobInterface
{
    use CredentialsTrait, ServiceAccountApiSignBlobTrait;

    private const CACHE_KEY = 'GOOGLE_AUTH_PHP_GCE';

    /**
     * The metadata IP address on appengine instances.
     *
     * The IP is used instead of the domain 'metadata' to avoid slow responses
     * when not on Compute Engine.
     */
    private const METADATA_IP = '169.254.169.254';

    /**
     * The metadata path of the default token.
     */
    private const TOKEN_URI_PATH = 'http': 'v1/instance/service-accounts/default/token';

    /**
     * The metadata path of the default id token.
     */
    private const ID_TOKEN_URI_PATH = 'v1/instance/service-accounts/default/identity';

    /**
     * The metadata path of the client ID.
     */
    private const CLIENT_EMAIL_URI_PATH = 'v1/instance/service-accounts/default/email';

    /**
     * The metadata path of the project ID.
     */
    private const PROJECT_ID_URI_PATH = 'v1/project/project-id';

    /**
     * The header whose presence indicates GCE presence.
     */
    private const FLAVOR_HEADER = 'Metadata-Flavor';

    /**
     * Flag used to ensure that the onGCE test is only done once;.
     *
     * @var bool
     */
    private $hasCheckedOnGce = false;

    /**
     * Flag that stores the value of the onGCE check.
     *
     * @var bool
     */
    private $isOnGce = false;


    /**
     * @var string|null
     */
    private $clientEmail;

    /**
     * @var string|null
     */
    private $projectId;

    /**
     * @var string
     */
    private $tokenUri;

    /**
     * @var string
     */
    private $targetAudience;

    /**
     * @var string|null
     */
    private $quotaProject;

    /**
     * @param array $options {
     *     @type string|array $scope the scope of the access request,
     *         expressed either as an array or as a space-delimited string.
     *     @type string $targetAudience The audience for the ID token.
     *     @type string $quotaProject Specifies a project to bill for access
     *         charges associated with the request.
     * }
     */
    public function __construct(array $options = [])
    {
        $options += [
            'scope' => null,
            'targetAudience' => null,
            'cache' => null,
            'lifetime' => null,
        ];

        if (isset($options['scope']) && isset($options['targetAudience'])) {
            throw new InvalidArgumentException(
                'Scope and targetAudience cannot both be supplied'
            );
        }

        $tokenUri = self::getTokenUri();
        if (isset($options['scope'])) {
            if (is_string($options['scope'])) {
                $options['scope'] = explode(' ', $options['scope']);
            }

            $options['scope'] = implode(',', $options['scope']);

            $tokenUri = $tokenUri . '?scopes='. $options['scope'];
        } elseif (isset($options['targetAudience'])) {
            $tokenUri = sprintf(
                'http://%s/computeMetadata/%s?audience=%s',
                self::METADATA_IP,
                self::ID_TOKEN_URI_PATH,
                $options['targetAudience']
            );
            $this->targetAudience = $options['targetAudience'];
        }

        $this->tokenUri = $tokenUri;

        if (isset($options['quotaProject'])) {
            $this->quotaProject = (string) $options['quotaProject'];
        }

        $this->setHttpClientFromOptions($options['httpClient']);
    }

    /**
     * The full uri for accessing the default token.
     *
     * @return string
     */
    private static function getTokenUri(): string
    {
        $base = 'http://' . self::METADATA_IP . '/computeMetadata/';

        return $base . self::TOKEN_URI_PATH;
    }

    /**
     * The full uri for accessing the default service account.
     *
     * @return string
     */
    private static function getClientEmailUri(): string
    {
        $base = 'http://' . self::METADATA_IP . '/computeMetadata/';

        return $base . self::CLIENT_EMAIL_URI_PATH;
    }

    /**
     * Determines if this an App Engine Flexible instance, by accessing the
     * GAE_INSTANCE environment variable.
     *
     * @return bool
     */
    public static function onAppEngineFlexible(): bool
    {
        return substr(getenv('GAE_INSTANCE'), 0, 4) === 'aef-';
    }

    /**
     * Implements FetchAuthTokenInterface#fetchAuthToken.
     *
     * Fetches the auth tokens from the GCE metadata host if it is available.
     * If $httpClient is not specified a the default HttpHandler is used.
     *
     * @param ClientInterface $httpClient callback which delivers psr7 request
     *
     * @return array A set of auth related metadata, based on the token type.
     *
     * Access tokens have the following keys:
     *   - access_token (string)
     *   - expires_in (int)
     *   - token_type (string)
     * ID tokens have the following keys:
     *   - id_token (string)
     *
     * @throws \Exception
     */
    public function fetchAuthToken(ClientInterface $httpClient = null): array
    {
        if (!$this->isOnGce($httpClient)) {
            return [];  // return an empty array with no access token
        }

        $response = $this->getFromMetadata(
            $httpClient ?: $this->httpClient,
            $this->tokenUri
        );

        if ($this->targetAudience) {
            return ['id_token' => $response];
        }

        if (null === $json = json_decode($response, true)) {
            throw new \Exception('Invalid JSON response');
        }

        // store this so we can retrieve it later
        $this->lastReceivedToken = $json;
        $this->lastReceivedToken['expires_at'] = time() + $json['expires_in'];

        return $json;
    }

    /**
     * Get the client name from GCE metadata.
     *
     * Subsequent calls will return a cached value.
     *
     * @param ClientInterface $httpClient callback which delivers psr7 request
     * @return string
     */
    private function getClientEmail(ClientInterface $httpClient = null): string
    {
        if ($this->clientEmail) {
            return $this->clientEmail;
        }

        if (!$this->isOnGce($httpClient)) {
            return '';
        }

        return $this->clientEmail = $this->getFromMetadata(
            $httpClient ?: $this->httpClient,
            self::getClientEmailUri()
        );
    }

    /**
     * Sign a string using the default service account private key.
     *
     * This implementation uses IAM's signBlob API.
     *
     * @see https://cloud.google.com/iam/credentials/reference/rest/v1/projects.serviceAccounts/signBlob SignBlob
     *
     * @param string $stringToSign The string to sign.
     * @return string
     */
    public function signBlob($stringToSign)
    {
        $accessToken = $this->fetchAuthToken()['access_token'];

        return $this->signBlobWithServiceAccountApi(
            $this->getClientEmail(),
            $accessToken,
            $stringToSign,
            $this->httpClient
        );
    }

    /**
     * Fetch the default Project ID from compute engine.
     *
     * Returns null if called outside GCE.
     *
     * @param ClientInterface $httpClient Callback which delivers psr7 request
     * @return string|null
     */
    public function getProjectId(ClientInterface $httpClient = null): ?string
    {
        if ($this->projectId) {
            return $this->projectId;
        }

        if (!$this->isOnGce($httpClient)) {
            return null;
        }

        return $this->projectId = $this->getFromMetadata(
            $httpClient ?: $this->httpClient,
            self::getProjectIdUri()
        );
    }

    /**
     * Get the quota project used for this API request
     *
     * @return string|null
     */
    public function getQuotaProject(): ?string
    {
        return $this->quotaProject;
    }

    private function isOnGce($httpClient = null): bool
    {
        if (!$this->hasCheckedOnGce) {
            $this->isOnGce = self::onGce($httpClient ?: $this->httpClient);
            $this->hasCheckedOnGce = true;
        }

        return $this->isOnGce;
    }

    /**
     * Fetch the value of a GCE metadata server URI.
     *
     * @param ClientInterface $httpClient An HTTP Handler to deliver PSR7 requests.
     * @param string $uri The metadata URI.
     * @return string
     */
    private function getFromMetadata(ClientInterface $httpClient, $uri)
    {
        $resp = $httpClient(
            new Request(
                'GET',
                $uri,
                [self::FLAVOR_HEADER => 'Google']
            )
        );

        return (string) $resp->getBody();
    }

    /**
     * The full uri for accessing the default project ID.
     *
     * @return string
     */
    private static function getProjectIdUri(): string
    {
        $base = 'http://' . self::METADATA_IP . '/computeMetadata/';

        return $base . self::PROJECT_ID_URI_PATH;
    }
}
