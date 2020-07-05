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

namespace Google\Auth\Tests;

use Google\Auth\GoogleAuth;
use Google\Auth\Credentials\ComputeCredentials;
use Google\Auth\Credentials\ServiceAccountCredentials;
use GuzzleHttp\Psr7;
use PHPUnit\Framework\TestCase;

class ADCGetTest extends TestCase
{
    private $originalHome;

    protected function setUp()
    {
        $this->originalHome = getenv('HOME');
    }

    protected function tearDown()
    {
        if ($this->originalHome != getenv('HOME')) {
            putenv('HOME=' . $this->originalHome);
        }
        putenv(ServiceAccountCredentials::ENV_VAR);  // removes it from
    }

    /**
     * @expectedException DomainException
     */
    public function testIsFailsEnvSpecifiesNonExistentFile()
    {
        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        GoogleAuth::getCredentials('a scope');
    }

    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope')
        );
    }

    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope')
        );
    }

    /**
     * @expectedException DomainException
     */
    public function testFailsIfNotOnGceAndNoDefaultFileFound()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);

        GoogleAuth::getCredentials('a scope', $httpHandler);
    }

    public function testSuccedsIfNoDefaultFilesButIsOnGCE()
    {
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $this->assertNotNull(
            GoogleAuth::getCredentials('a scope', $httpHandler)
        );
    }
}

class ADCGetMiddlewareTest extends TestCase
{
    private $originalHome;

    protected function setUp()
    {
        $this->originalHome = getenv('HOME');
    }

    protected function tearDown()
    {
        if ($this->originalHome != getenv('HOME')) {
            putenv('HOME=' . $this->originalHome);
        }
        putenv(ServiceAccountCredentials::ENV_VAR);  // removes it if assigned
    }

    /**
     * @expectedException DomainException
     */
    public function testIsFailsEnvSpecifiesNonExistentFile()
    {
        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        GoogleAuth::getMiddleware('a scope');
    }

    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        $this->assertNotNull(GoogleAuth::getMiddleware('a scope'));
    }

    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        $this->assertNotNull(GoogleAuth::getMiddleware('a scope'));
    }

    /**
     * @expectedException DomainException
     */
    public function testFailsIfNotOnGceAndNoDefaultFileFound()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);

        GoogleAuth::getMiddleware('a scope', $httpHandler);
    }

    public function testWithCacheOptions()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $httpHandler = getHandler([
            buildResponse(200),
        ]);

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $middleware = GoogleAuth::getMiddleware(
            'a scope',
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal()
        );
    }

    public function testSuccedsIfNoDefaultFilesButIsOnGCE()
    {
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $this->assertNotNull(GoogleAuth::getMiddleware('a scope', $httpHandler));
    }
}

class ADCGetCredentialsWithTargetAudienceTest extends TestCase
{
    private $originalHome;
    private $targetAudience = 'a target audience';

    protected function setUp()
    {
        $this->originalHome = getenv('HOME');
    }

    protected function tearDown()
    {
        if ($this->originalHome != getenv('HOME')) {
            putenv('HOME=' . $this->originalHome);
        }
        putenv(ServiceAccountCredentials::ENV_VAR);  // removes environment variable
    }

    /**
     * @expectedException DomainException
     */
    public function testIsFailsEnvSpecifiesNonExistentFile()
    {
        $keyFile = __DIR__ . '/fixtures' . '/does-not-exist-private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        GoogleAuth::getIdTokenCredentials($this->targetAudience);
    }

    public function testLoadsOKIfEnvSpecifiedIsValid()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);
        GoogleAuth::getIdTokenCredentials($this->targetAudience);
    }

    public function testLoadsDefaultFileIfPresentAndEnvVarIsNotSet()
    {
        putenv('HOME=' . __DIR__ . '/fixtures');
        GoogleAuth::getIdTokenCredentials($this->targetAudience);
    }

    /**
     * @expectedException DomainException
     */
    public function testFailsIfNotOnGceAndNoDefaultFileFound()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        // simulate not being GCE and retry attempts by returning multiple 500s
        $httpHandler = getHandler([
            buildResponse(500),
            buildResponse(500),
            buildResponse(500)
        ]);

        GoogleAuth::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );
    }

    public function testWithCacheOptions()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $httpHandler = getHandler([
            buildResponse(200),
        ]);

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $credentials = GoogleAuth::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal()
        );

        $this->assertInstanceOf('Google\Auth\FetchAuthTokenCache', $credentials);
    }

    public function testSuccedsIfNoDefaultFilesButIsOnGCE()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $credentials = GoogleAuth::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $credentials
        );
    }
}

class ADCGetCredentialsWithQuotaProjectTest extends TestCase
{
    private $originalHome;
    private $quotaProject = 'a-quota-project';

    protected function setUp()
    {
        $this->originalHome = getenv('HOME');
    }

    protected function tearDown()
    {
        if ($this->originalHome != getenv('HOME')) {
            putenv('HOME=' . $this->originalHome);
        }
        putenv(ServiceAccountCredentials::ENV_VAR);  // removes environment variable
    }

    public function testWithServiceAccountCredentials()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $credentials = GoogleAuth::getCredentials(
            null,
            null,
            null,
            null,
            $this->quotaProject
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ServiceAccountCredentials',
            $credentials
        );

        $this->assertEquals(
            $this->quotaProject,
            $credentials->getQuotaProject()
        );
    }

    public function testWithFetchAuthTokenCache()
    {
        $keyFile = __DIR__ . '/fixtures' . '/private.json';
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $keyFile);

        $httpHandler = getHandler([
            buildResponse(200),
        ]);

        $cacheOptions = [];
        $cachePool = $this->prophesize('Psr\Cache\CacheItemPoolInterface');

        $credentials = GoogleAuth::getCredentials(
            null,
            $httpHandler,
            $cacheOptions,
            $cachePool->reveal(),
            $this->quotaProject
        );

        $this->assertInstanceOf('Google\Auth\FetchAuthTokenCache', $credentials);

        $this->assertEquals(
            $this->quotaProject,
            $credentials->getQuotaProject()
        );
    }

    public function testWithComputeCredentials()
    {
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');
        $wantedTokens = [
            'access_token' => '1/abdef1234567890',
            'expires_in' => '57',
            'token_type' => 'Bearer',
        ];
        $jsonTokens = json_encode($wantedTokens);

        // simulate the response from GCE.
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
            buildResponse(200, [], Psr7\stream_for($jsonTokens)),
        ]);

        $credentials = GoogleAuth::getCredentials(
            null,
            $httpHandler,
            null,
            null,
            $this->quotaProject
        );

        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $credentials
        );

        $this->assertEquals(
            $this->quotaProject,
            $credentials->getQuotaProject()
        );
    }
}

class ADCGetCredentialsAppEngineTest extends BaseTest
{
    private $originalHome;
    private $originalServiceAccount;
    private $targetAudience = 'a target audience';

    protected function setUp()
    {
        // set home to be somewhere else
        $this->originalHome = getenv('HOME');
        putenv('HOME=' . __DIR__ . '/not_exist_fixtures');

        // remove service account path
        $this->originalServiceAccount = getenv(ServiceAccountCredentials::ENV_VAR);
        putenv(ServiceAccountCredentials::ENV_VAR);
    }

    protected function tearDown()
    {
        // removes it if assigned
        putenv('HOME=' . $this->originalHome);
        putenv(ServiceAccountCredentials::ENV_VAR . '=' . $this->originalServiceAccount);
        putenv('GAE_INSTANCE');
    }

    public function testAppEngineStandard()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        $this->assertInstanceOf(
            'Google\Auth\Credentials\AppIdentityCredentials',
            GoogleAuth::getCredentials()
        );
    }

    public function testAppEngineFlexible()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
        ]);
        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            GoogleAuth::getCredentials(null, $httpHandler)
        );
    }

    public function testAppEngineFlexibleIdToken()
    {
        $_SERVER['SERVER_SOFTWARE'] = 'Google App Engine';
        putenv('GAE_INSTANCE=aef-default-20180313t154438');
        $httpHandler = getHandler([
            buildResponse(200, [ComputeCredentials::FLAVOR_HEADER => 'Google']),
        ]);
        $creds = GoogleAuth::getIdTokenCredentials(
            $this->targetAudience,
            $httpHandler
        );
        $this->assertInstanceOf(
            'Google\Auth\Credentials\ComputeCredentials',
            $creds
        );
    }
}
