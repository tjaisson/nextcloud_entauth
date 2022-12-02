<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\AppInfo;

use OCP\AppFramework\App;
use OCP\AppFramework\Bootstrap\IBootContext;
use OCP\AppFramework\Bootstrap\IBootstrap;
use OCP\AppFramework\Bootstrap\IRegistrationContext;
use OCP\User\Events\UserDeletedEvent;

use OCA\EntAuth\Event\UserDeleteListener;
use OCA\EntAuth\Security\TokenServiceInterface;
use OCA\EntAuth\Security\Impl\TokenService;

class Application extends App implements IBootstrap {
	public const APP_ID = 'entauth';

	public function __construct()
	{
		parent::__construct(self::APP_ID);
	}

	public function register(IRegistrationContext $context): void
	{
		$context->registerEventListener(
			UserDeletedEvent::class,
			UserDeleteListener::class
		);
		$context->registerServiceAlias(
			TokenServiceInterface::class,
			TokenService::class
		);
	}

	public function boot(IBootContext $context): void
	{
		
	}
}
