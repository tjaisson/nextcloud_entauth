<?php
namespace OCA\EntcoreAuth;

class Oauth {
    
    public function getConnector($srv) {
        if(($srv !== 'mln') && ($srv !== 'pcn')) return false;
    }
}

class Connector {
    public function getToken($code) {
        
    }
    
    public function getUserdata($tk) {
        
    }
    
    public function getLoginUrl($state) {
        
    }
}