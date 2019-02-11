<?php
namespace OCA\EntAuth;

class AuthServices {
    private $config;

    private function getConfig() {
        if(!isset($this->config)) {
            $ENTCONF = false;
            include OC::$configDir.'entconf.php';
            if(!$ENTCONF) $ENTCONF = [];
            $this->config = $ENTCONF;
        }
        return $this->config;
    }

    public function getProvider($srv) {
        $c = $this->getConfig();
        if(!\array_key_exists($srv, $c)) return false;
        $conf = $c[$srv];
        $class = __NAMESPACE__ . '\\Providers\\' .$conf['type'] . 'Provider';
        return new $class($c[$srv]);
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
    private $config;
    
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
}

abstract class UserData {
    public $userId;
    public abstract function ExtractDigest();
}