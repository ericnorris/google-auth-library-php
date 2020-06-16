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

use Google\Http\ClientInterface;

/**
 * An interface implemented by objects that can fetch auth tokens.
 */
interface CredentialsInterface
{
    /**
     * Fetches the auth tokens based on the current state.
     *
     * @param callable $httpClient callback which delivers psr7 request
     * @return array a hash of auth tokens
     */
    public function fetchAuthToken(ClientInterface $httpClient = null): array;

    public function getRequestMetadata(
        ClientInterface $httpClient = null
    ): array;

    public function setCache(CacheInterface $cache): void;
}
