<?php
/**
 * Exemple de fichier de configuration
 * Copiez ce fichier dans le répertoire config de nextcloud
 * en le renommant entauth.config.php
 * 
 * Les clefs 'ent1', 'ent2' sont utilisées pour former les url
 * de connexion
 * 
 * Le champ 'dbId' est un entier qui doit être différent pour chaque ent.
 * Le 'dbId' d'un ent ne doit pas être changé par la suite
 * 
 * Le type Entcore est le seul actuellement implémenté.
 */
return [
  'ent1' => [
    'name' => 'Ent1 display name',
    'dbId' => 1,
    'host' => 'ent1.host.xyz',
    'appId' => 'the app id 1',
    'secret' => 'the secret 1',
    'type' => 'Entcore'
  ],
  'ent2' => [
    'name' => 'Ent2 display name',
    'dbId' => 2,
    'host' => 'ent2.host.xyz',
    'appId' => 'the app id 2',
    'secret' => 'the secret 2',
    'type' => 'Entcore'
  ]
];