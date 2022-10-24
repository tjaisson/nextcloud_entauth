<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

return [
    'routes' => [
        ['name' => 'page#index', 'url' => '/', 'verb' => 'GET'],
        ['name' => 'page#login', 'url' => '/{srv}', 'verb' => 'GET'],
        ['name' => 'page#associate', 'url' => '/{srv}', 'verb' => 'POST'],
    ]
];
