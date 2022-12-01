<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\AppInfo;

use OCP\AppFramework\App;
use OCP\EventDispatcher\IEventDispatcher;
use OCP\User\Events\BeforeUserDeletedEvent;

use OCA\EntAuth\Event\UserDeleteListener;

class Application extends App {
	public const APP_ID = 'entauth';

	public function __construct() {
		parent::__construct(self::APP_ID);
		/** @var IEventDispatcher $dispatcher */
		$dispatcher = $this->getContainer()->get(IEventDispatcher::class);
		$dispatcher->addServiceListener(
			BeforeUserDeletedEvent::class,
			UserDeleteListener::class);
	}
}
