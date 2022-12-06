<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth;

use OCP\Http\Client\IClientService;

class AuthServices {
    const CONF_FILE = 'entauth.config.php';
    private $config;
	/** @var IClientService */
	private $clientService;

    public function __construct(IClientService $cs)
    {
        $this->clientService = $cs;
    }

    private function getConfig() {
        if(!isset($this->config)) {
            $ENTCONF = include \OC::$configDir . self::CONF_FILE;
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
        return new $class($conf, $this->clientService);
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
