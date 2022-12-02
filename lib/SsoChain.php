<?php

declare(strict_types=1);

/**
 * @copyright 2019 Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @author Christoph Wurst <christoph@winzerhof-wurst.at>
 *
 * @license GNU AGPL version 3 or any later version
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 */
namespace OCA\EntAuth;

use OC\Authentication\Login\LoginData;
use OC\Authentication\Login\LoginResult;
use OC\Authentication\Login\UserDisabledCheckCommand;
use OC\Authentication\Login\CompleteLoginCommand;
use OC\Authentication\Login\CreateSessionTokenCommand;
use OC\Authentication\Login\SetUserTimezoneCommand;


class SsoChain {

	/** @var UserDisabledCheckCommand */
	private $userDisabledCheckCommand;

	/** @var CompleteLoginCommand */
	private $completeLoginCommand;

	/** @var CreateSessionTokenCommand */
	private $createSessionTokenCommand;

	/** @var SetUserTimezoneCommand */
	private $setUserTimezoneCommand;

	public function __construct(UserDisabledCheckCommand $userDisabledCheckCommand,
								CompleteLoginCommand $completeLoginCommand,
								CreateSessionTokenCommand $createSessionTokenCommand,
								SetUserTimezoneCommand $setUserTimezoneCommand,
	) {
		$this->userDisabledCheckCommand = $userDisabledCheckCommand;
		$this->completeLoginCommand = $completeLoginCommand;
		$this->createSessionTokenCommand = $createSessionTokenCommand;
		$this->setUserTimezoneCommand = $setUserTimezoneCommand;
	}

	public function process(LoginData $loginData): LoginResult {
		$chain = $this->userDisabledCheckCommand;
		$chain
			->setNext($this->completeLoginCommand)
			->setNext($this->createSessionTokenCommand)
			->setNext($this->setUserTimezoneCommand);

		return $chain->process($loginData);
	}
}
