<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Providers;

use OCA\EntAuth\Providers\Provider;
use OCA\EntAuth\Providers\EntcoreUserData;

class EntcoreProvider extends Provider {
    public function getToken($code) {
        $url = $this->config['host'];
        $url = "https://{$url}/auth/oauth2/token";
        $dt = [
            'grant_type' => 'authorization_code',
            'code' => $code,
            'redirect_uri' => $this->redirectUri
        ];
        $rep = $this->doPostRequest($url, $dt, $this->config['appId'], $this->config['secret']);
        $rep = \json_decode($rep);
        return $rep->access_token;
    }

    public function getUserdata($tk) {
        $url = $this->config['host'];
        $url = "https://{$url}/auth/oauth2/userinfo";
        $rep = $this->doGetRequest($url, $tk);
        $rep = \json_decode($rep);
        return new EntcoreUserData($rep);
    }

    public function getLoginUrl($state) {
        $params = [];
        $params['scope'] = 'userinfo';
        $params['response_type'] = 'code';
        $params['approval_prompt'] = 'auto';
        $params['client_id'] = $this->config['appId'];
        $params['redirect_uri'] = \urlencode($this->redirectUri);
        $params['state'] = $state;
        $url = $this->config['host'];
        $url = "https://{$url}/auth/oauth2/auth";
        return $this->buildUrl($url, $params);
    }
}
