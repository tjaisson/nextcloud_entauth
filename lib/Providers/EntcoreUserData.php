<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Providers;

use OCA\EntAuth\Providers\UserData;

class EntcoreUserData extends UserData {
    private $data;
    
    function __construct($data) {
        $this->data = $data;
        $this->userId = $data->login;
    }
    
    public function ExtractDigest() {
        return [
            'firstname' => $this->data->firstName,
            'lastname' => $this->data->lastName,
            'login' => $this->data->login,
        ];
    }
}