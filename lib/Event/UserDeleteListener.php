<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Event;

use OCP\EventDispatcher\Event;
use OCP\EventDispatcher\IEventListener;
use OCP\User\Events\BeforeUserDeletedEvent;

use OCA\EntAuth\ExternalIds;

class UserDeleteListener implements IEventListener {
    /** @var ExternalIds */
    protected $ext;
    public function __construct(ExternalIds $ext)
    {
        $this->ext = $ext;
    }

    public function handle(Event $event): void {
        if (!($event instanceOf BeforeUserDeletedEvent)) {
            return;
        }
        $this->ext->DeleteUser($event->getUser()->getUID());
    }
}