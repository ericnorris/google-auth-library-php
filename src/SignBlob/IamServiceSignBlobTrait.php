<?php
/*
 * Copyright 2019 Google LLC
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

namespace Google\Auth\SignBlob;

use Google\Auth\HttpHandler\HttpClientCache;
use Google\Auth\HttpHandler\HttpHandlerFactory;
use GuzzleHttp\Psr7;

/**
 * Tools for using the IAM API.
 *
 * @see https://cloud.google.com/iam/docs IAM Documentation
 */
trait IamServiceSignBlobTrait
{
    /**
     * Sign a string using the IAM signBlob API.
     *
     * Note that signing using IAM requires your service account to have the
     * `iam.serviceAccounts.signBlob` permission, part of the "Service Account
     * Token Creator" IAM role.
     *
     * @param string $email The service account email.
     * @param string $accessToken An access token from the service account.
     * @param string $stringToSign The string to be signed.
     * @param array $delegates [optional] A list of service account emails to
     *        add to the delegate chain. If omitted, the value of `$email` will
     *        be used.
     * @return string The signed string, base64-encoded.
     */
    private function signBlob(
        ClientInterface $httpClient,
        string $email,
        string $accessToken,
        string $stringToSign,
        array $delegates = []
    ): string {
        $name = sprintf('projects/-/serviceAccounts/%s', $email);
        $uri = sprintf(
            'https://iamcredentials.googleapis.com/v1/%s:signBlob?alt=json',
            $name
        );

        if ($delegates) {
            foreach ($delegates as &$delegate) {
                $delegate = sprintf('projects/-/serviceAccounts/%s', $delegate);
            }
        } else {
            $delegates = [$name];
        }

        $body = [
            'delegates' => $delegates,
            'payload' => base64_encode($stringToSign),
        ];

        $headers = [
            'Authorization' => 'Bearer ' . $accessToken
        ];

        $request = new Psr7\Request(
            'POST',
            $uri,
            $headers,
            Psr7\stream_for(json_encode($body))
        );

        $res = $httpClient->send($request);
        $body = json_decode((string) $res->getBody(), true);

        return $body['signedBlob'];
    }
}
