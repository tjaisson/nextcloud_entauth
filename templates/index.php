<?php
style('entauth', 'style');
?>

<form id="ent-logins">
	<fieldset>
		<ul>

<?php foreach($_['providers'] as $prov) : ?> 
	<li><a class="button" href="<?php print_unescaped($prov['url']); ?>" ><?php p($prov['name']); ?></a></li>
<?php endforeach; ?>
<li><a class="button" href="<?php print_unescaped($_['backUrl']); ?>">Retour</a></li>
		</ul>
	</fieldset>
</form>