<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Providers;

use OCP\Http\Client\IClientService;
use OCP\AppFramework\Http;

abstract class Provider {
    protected $config;
    protected $redirectUri;
   	/** @var IClientService */
	private $clientService;

    function __construct($conf, $cs) {
        $this->config = $conf;
        $this->clientService = $cs;
    }

    public abstract function getToken($code);
    public abstract function getUserdata($tk);
    public abstract function getLoginUrl($state);
    public function getDbId(){
        return $this->config['dbId'];
    }
    public function getName(){
        return $this->config['name'];
    }
    public function getSrv(){
        return $this->config['srv'];
    }
    public function setRedirectUri($uri) {
        $this->redirectUri = $uri;
    }
    
    protected function initCurl() {
        if (!function_exists('curl_init')){
            throw new \Exception('CURL must be present');
        }
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_USERAGENT, "MozillaXYZ/1.0");
        curl_setopt($ch, CURLOPT_HEADER, 0);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 30);
        //curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        //curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        return $ch;
    }
    
    protected function doPostRequest($url, $dt, $id, $pw) {
        $client = $this->clientService->newClient();
        $creds = \base64_encode("{$id}:{$pw}");
        $resp = $client->post(
            $url,
            ['headers' => ["Authorization: Basic {$creds}"]]
        );
        if ($resp->getStatusCode() != Http::STATUS_OK) return false;
        return $resp->getBody();
    }

    protected function doGetRequest($url, $tk) {
        $client = $this->clientService->newClient();
        $resp = $client->get(
            $url,
            ['headers' => ["Authorization: Bearer {$tk}"]]
        );
        if ($resp->getStatusCode() != Http::STATUS_OK) return false;
        return $resp->getBody();
    }

    protected function buildUrl($url, $params)
    {
        $url .= '?';
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
