<?php
script('entauth', 'script');
style('entauth', 'style');
?>

<?php foreach($_['providers'] as $prov) : ?> 
	<p><a class="button" href="<?php print_unescaped($prov['url']); ?>" ><?php p($prov['name']); ?></a></p>
<?php endforeach; ?>
<p><a class="button" href="<?php print_unescaped($_['backUrl']); ?>">Retour</a></p>

