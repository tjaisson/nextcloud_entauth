<?php
namespace OCA\EntAuth;

use OCP\Files\IAppData;
use OCP\Files\NotFoundException;


class Crypt {
    const fld = 'crypt';
    const keys = 'keys';
    const lock = 'lock';
    const method = 'aes128';
    const period = 600;
    private $appData;
    private $cyphKey;
    private $decyphKeys;
    
    
    public function __construct(IAppData $appData) {
        $this->appData = $appData;
    }
 
    public function seal($str){
        $c = $this->getCyphKey();
        return $c['keyId'] . $this->base64_url_encode(\openssl_encrypt($str, self::method, $c->k, \OPENSSL_RAW_DATA, $c->iv));
    }
    
    public function open($str){
        $c = $this->getDecyphKey(\substr($str, 0, 3));
        if(!$c) return false;
        $str = $this->base64_url_decode(\substr($str, 3));
        return  \openssl_decrypt($str, self::method, $c->k, \OPENSSL_RAW_DATA, $c->iv);
    }

    private function base64_url_encode($input) {
        return strtr(base64_encode($input), '+/=', '._-');
    }
    
    private function base64_url_decode($input) {
        return base64_decode(strtr($input, '._-', '+/='));
    }
    
    private function getStoreFiles() {
        try {
            $fld = $this->appData->getFolder(self::fld);
        } catch (NotFoundException $e) {
            $fld = $this->appData->newFolder(self::fld);
        }
        try {
            $l = $fld->getFile(self::lock);
        } catch (NotFoundException $e) {
            $l = $fld->newFile(self::lock);
        }
        try {
            $k = $fld->getFile(self::keys);
        } catch (NotFoundException $e) {
            $k = $fld->newFile(self::keys);
        }
        return ['lock' => $l, 'keys' => $k];
    }
    
    private function getDecyphKey($keyId) {
        if(!$this->decyphKeys) {
            $files = $this->getStoreFiles();
            $oLock = $files['lock']->read();
            if(!oLock) {
                $files['lock']->getContent();
                return false;
            }
            try {
                if(\flock($oLock, \LOCK_SH)) {
                    try {
                        $this->decyphKeys = \json_decode($files['keys']->getContent());
                    } finally {
                        \flock($oLock, \LOCK_UN);
                    }
                } else {
                    $files['lock']->getContent();
                    return false;
                }
            } finally {
                \fclose($oLock);
            }
        }
        $s = $this->decyphKeys;
        if(!$s) return false;
        $k = $keyId[0];
        $v = (int)\substr($keyId, 1);
        $cs = $s->{$k};
        if(!cs) return false;
        if($cs->v !== $v) return false;
        $t =  \time() - 2 * self::period;
        if($cs->t < $t) return false;
        return   ['key' => \base64_decode($cs->k), 'iv' => \base64_decode($cs->iv)];
    }
    
    private function getCyphKey() {
        if($this->cyphKey) return $this->cyphKey;
        $t = \time() - self::period;
        $files = $this->getStoreFiles();
        $oLock = $files['lock']->read();
        if(!oLock) {
            $files['lock']->getContent();
            return false;
        }
        try {
            if(\flock($oLock, \LOCK_SH)) {
                try {
                    $s = \json_decode($files['keys']->getContent());
                } finally {
                    \flock($oLock, \LOCK_UN);
                }
                if($s && $s->c) {
                    $k = $s->{$s->c};
                    if($k && ($k->t > $t)) {
                        $this->cyphKey = ['keyId' => "{$s->c}{$k->v}", 'key' => \base64_decode($k->k), 'iv' => \base64_decode($k->iv)];
                        return $this->cyphKey;
                    }
                }
            } else {
                $files['lock']->getContent();
                return false;
            }
            //need to rotate key
            $this->decyphKeys = false;
            if(\flock($oLock, \LOCK_EX)) {
                try {
                    $s = \json_decode($files['keys']->getContent());
                    if(!$s) $s = new \stdClass();
                    if(!$s-c) $s->c = 'b';
                    $k = $s->{$s->c};
                    if($k && ($k->t > $t)) {
                        $this->cyphKey = ['keyId' => "{$s->c}{$k->v}", 'key' => \base64_decode($k->k), 'iv' => \base64_decode($k->iv)];
                        return $this->cyphKey;
                    }
                    $s->c = ($s->c === 'a') ? 'b' : 'a';
                    $k = $s->{$s->c};
                    if(!$k) {
                        $k = new \stdClass();
                        $k->v = 10;
                        $s->{$s->c} = $k;
                    }
                    $k->t = \time();
                    $k->v = ($k->v >= 99) ? 10 : $k->v + 1;
                    //generate key
                    $ivSize = \openssl_cipher_iv_length(self::method);
                    $ivb = \openssl_random_pseudo_bytes($ivSize);
                    $kb = \openssl_random_pseudo_bytes($ivSize);
                    $k->iv = \base64_encode($ivb);
                    $k->k = \base64_encode($kb);
                    $files['keys']->putContent(\json_encode($s));
                    $this->cyphKey = ['keyId' => "{$s->c}{$k->v}", 'key' => $kb, 'iv' => $ivb];
                    return $this->cyphKey;
                } finally {
                    \flock($oLock, \LOCK_UN);
                }
            } else {
                $files['lock']->getContent();
                return false;
            }
        } finally {
            \fclose($oLock);
        }
    }
}