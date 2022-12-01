<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Providers;

use OCA\EntAuth\Provider;
use OCA\EntAuth\UserData;

class EntcoreProvider extends Provider {
    public function getToken($code) {
        $url = $this->config['host'];
        $url = "https://{$url}/auth/oauth2/token";
        $redirectUri = \urlencode($this->redirectUri);
        $dt = "grant_type=authorization_code&code={$code}&redirect_uri={$redirectUri}";
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
        $url = "https://{$url}/auth/oauth2/auth?";
        $started = false;
        foreach ($params as $key => $value) {
            if ($started) {
                $url .= '&';
            } else {
                $started = true;
            }
            $url .= "{$key}={$value}";
        }
        return $url;
    }
}

class EntcoreUserData extends UserData {
    private $data;
    
    function __construct($data) {
        $this->data = $data;
        $this->userId = $data->externalId;
    }
    
    public function ExtractDigest() {
        return [
            'firstname' => $this->data->firstName,
            'lastname' => $this->data->lastName,
            'login' => $this->data->login,
        ];
    }
}