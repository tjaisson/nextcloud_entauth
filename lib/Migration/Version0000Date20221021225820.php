<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Migration;

use Closure;
use OCP\DB\ISchemaWrapper;
use OCP\Migration\SimpleMigrationStep;
use OCP\Migration\IOutput;

class Version0000Date20221021225820 extends SimpleMigrationStep {

	/**
	 * @param IOutput $output
	 * @param Closure $schemaClosure The `\Closure` returns a `ISchemaWrapper`
	 * @param array $options
	 * @return null|ISchemaWrapper
	 */
	public function changeSchema(IOutput $output, Closure $schemaClosure, array $options) {
		/** @var ISchemaWrapper $schema */
		$schema = $schemaClosure();

		$table = $schema->createTable('entauth_keys');
		$table->addColumn('id', 'integer', [
			'unsigned' => true,
			'notnull' => true,
		]);
		$table->addColumn('sign', 'binary', [
			'notnull' => true,
			'length' => 64,
		]);
		$table->addColumn('cypher', 'binary', [
			'notnull' => true,
			'length' => 64,
		]);
		$table->addColumn('exp', 'bigint', [
			'unsigned' => true,
			'notnull' => true,
		]);
		$table->setPrimaryKey(['id']);
		$table->addIndex(['exp']);

		$table = $schema->createTable('entauth_nonces');
		$table->addColumn('val', 'bigint', [
			'unsigned' => true,
			'notnull' => true,
		]);
		$table->addColumn('exp', 'bigint', [
			'unsigned' => true,
			'notnull' => true,
		]);
		$table->setPrimaryKey(['val']);
		$table->addIndex(['exp']);
		
		return $schema;
	}
}
