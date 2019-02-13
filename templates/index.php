<?php
script('entauth', 'script');
style('entauth', 'style');
?>

<div id="app">
	<div id="app-content">
	<ul>
	<?php foreach($_['providers'] as $prov) : ?> 
		<li><a class="button" href="<?php print_unescaped($prov['url']); ?>" ><?php p($prov['name']); ?></a></li>
	<?php endforeach; ?>
	<li><a class="button" href="<?php print_unescaped($_['backUrl']); ?>" >Retour</a></li>
	</ul>
	</div>
	<p><?php p($l->t('Log in')); ?></p>
</div>

