<?php
namespace OCA\EntAuth\Providers;

use OCA\EntAuth\Provider;
use OCA\EntAuth\UserData;

class EntcoreProvider extends Provider {
    public function getToken($code) {
        
    }
    
    public function getUserdata($tk) {
        
        return new EntcoreUserData($data);
    }
    
    public function getLoginUrl($state) {
        
    }
}

class EntcoreUserData extends UserData {
    private $data;
    
    function __construct($data) {
        $this->data = $data;
        $this->userId = $data->userId;
    }
    
    public function ExtractDigest() {
        return [
            'firstname' => $this->data->firstname,
            'lastname' => $this->data->lastname,
        ];
    }
}