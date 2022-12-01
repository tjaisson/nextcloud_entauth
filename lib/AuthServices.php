<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth;

class AuthServices {
    private $config;

    private function getConfig() {
        if(!isset($this->config)) {
            $ENTCONF = false;
            include \OC::$configDir.'entconf.php';
            if(!$ENTCONF) $ENTCONF = [];
            $this->config = $ENTCONF;
        }
        return $this->config;
    }

    public function getProvider($srv) {
        $c = $this->getConfig();
        if(!\array_key_exists($srv, $c)) return false;
        $conf = $c[$srv];
        $conf['srv'] = $srv;
        $class = __NAMESPACE__ . '\\Providers\\' .$conf['type'] . 'Provider';
        return new $class($conf);
    }

    public function listProviders() {
        $c = $this->getConfig();
        $l = [];
        foreach($c as $k => $v) {
            $prov = $this->getProvider($k);
            $l[] = [
                'name' => $prov->getName(),
                'srv' => $k,
            ];
        }
        return $l;
    }
}

abstract class Provider {
    protected $config;
    protected $redirectUri;
    
    function __construct($conf) {
        $this->config = $conf;
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
        $ch = $this->initCurl();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $dt);
        $creds = \base64_encode("{$id}:{$pw}");
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Basic {$creds}"]);
        $output = curl_exec($ch);
        curl_close($ch);
        return $output;
    }

    protected function doGetRequest($url, $tk) {
        $ch = $this->initCurl();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer {$tk}"]);
        $output = curl_exec($ch);
        curl_close($ch);
        return $output;
    }
    
    
}

abstract class UserData {
    public $userId;
    public abstract function ExtractDigest();
}