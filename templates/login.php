<?php /** @var $l \OCP\IL10N */ ?>
<?php
vendor_script('jsTimezoneDetect/jstz');
//script('core', 'merged-login');
style('entauth', 'style');

use OC\Core\Controller\LoginController;
$ll = $_['l'];
?>

<!--[if IE 8]><style>input[type="checkbox"]{padding:0;}</style><![endif]-->

<div class="warning">
<p>Vous êtes authentifié dans l'ENT</p>
<p>ENT&nbsp;: <?php p($_['prov'])?></p>
<p><?php p($_['user']['firstname'] . ' ' . $_['user']['lastname'] )?></p>
</div>

<div class="warning">
<p>Votre compte ENT n'est associé à aucun compte synbox</p>
</div>

<div class="warning">
<p>Vous pouvez associer votre compte ENT à votre compte synbox en vous authentifiant</p>
</div>

<form method="post" name="login" action="<?php p($_['actionUrl']) ?>">
	<fieldset>
		<?php if (isset($_['apacheauthfailed']) && $_['apacheauthfailed']): ?>
			<div class="warning">
				<?php p($ll->t('Server side authentication failed!')); ?><br>
				<small><?php p($ll->t('Please contact your administrator.')); ?></small>
			</div>
		<?php endif; ?>
		<?php foreach($_['messages'] as $message): ?>
			<div class="warning">
				<?php p($message); ?><br>
			</div>
		<?php endforeach; ?>
		<?php if (isset($_['internalexception']) && $_['internalexception']): ?>
			<div class="warning">
				<?php p($ll->t('An internal error occurred.')); ?><br>
				<small><?php p($ll->t('Please try again or contact your administrator.')); ?></small>
			</div>
		<?php endif; ?>
		<div id="message" class="hidden">
			<img class="float-spinner" alt=""
				src="<?php p(image_path('core', 'loading-dark.gif'));?>">
			<span id="messageText"></span>
			<!-- the following div ensures that the spinner is always inside the #message div -->
			<div style="clear: both;"></div>
		</div>	
		<p class="grouptop<?php if (!empty($_[LoginController::LOGIN_MSG_INVALIDPASSWORD])) { ?> shake<?php } ?>">
			<input type="text" name="user" id="user"
				placeholder="<?php p($ll->t('Username or email')); ?>"
				aria-label="<?php p($ll->t('Username or email')); ?>"
				value="<?php p($_['loginName']); ?>"
				<?php p($_['user_autofocus'] ? 'autofocus' : ''); ?>
				autocomplete="<?php p($_['login_form_autocomplete']); ?>" autocapitalize="none" autocorrect="off" required>
			<label for="user" class="infield"><?php p($ll->t('Username or email')); ?></label>
		</p>

		<p class="groupbottom<?php if (!empty($_[LoginController::LOGIN_MSG_INVALIDPASSWORD])) { ?> shake<?php } ?>">
			<input type="password" name="password" id="password" value=""
				placeholder="<?php p($ll->t('Password')); ?>"
				aria-label="<?php p($ll->t('Password')); ?>"
				<?php p($_['user_autofocus'] ? '' : 'autofocus'); ?>
				autocomplete="<?php p($_['login_form_autocomplete']); ?>" autocapitalize="none" autocorrect="off" required>
			<label for="password" class="infield"><?php p($ll->t('Password')); ?></label>
		</p>

		<div id="submit-wrapper">
			<input type="submit" id="submit" class="login primary" title="" value="Associer mon compte" disable="disabled" />
		</div>

		<?php if (!empty($_[LoginController::LOGIN_MSG_INVALIDPASSWORD])) { ?>
			<p class="warning wrongPasswordMsg">
				<?php p($ll->t('Wrong password.')); ?>
			</p>
		<?php } else if (!empty($_[LoginController::LOGIN_MSG_USERDISABLED])) { ?>
			<p class="warning userDisabledMsg">
				<?php p(\OC::$server->getL10N('lib')->t('User disabled')); ?>
			</p>
		<?php } ?>

		<?php if ($_['throttle_delay'] > 5000) { ?>
			<p class="warning throttledMsg">
				<?php p($ll->t('We have detected multiple invalid login attempts from your IP. Therefore your next login is throttled up to 30 seconds.')); ?>
			</p>
		<?php } ?>

		<input type="hidden" name="timezone_offset" id="timezone_offset"/>
		<input type="hidden" name="timezone" id="timezone"/>
		<input type="hidden" name="tk" value="<?php p($_['tk']) ?>">
		<input type="hidden" name="requesttoken" value="<?php p($_['requesttoken']) ?>">
	</fieldset>
</form>
<form id="ent-logins">
	<fieldset>
		<ul>
<li><a class="button" href="<?php print_unescaped($_['backUrl']); ?>">Retour</a></li>
		</ul>
	</fieldset>
</form>
<script nonce="<?php p(\OC::$server->getContentSecurityPolicyNonceManager()->getNonce()) ?>">
history.replaceState({}, "login", "<?php p($_['actionUrl']) ?>");
</script>