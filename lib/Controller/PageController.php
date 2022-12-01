<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Controller;

use OCP\AppFramework\Controller;
use OCP\IRequest;
use OCP\IUserSession;
use OCP\IUserManager;
use OCP\IURLGenerator;
use OCP\ILogger;
use OC\Security\CSRF\CsrfToken;
use OC\Security\CSRF\CsrfTokenManager;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\AppFramework\Http\Template\PublicTemplateResponse;
use OCP\AppFramework\Http\NotFoundResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OC\Core\Controller\LoginController;
use OCA\EntAuth\AuthServices;
use OCA\EntAuth\ExternalIds;
use OCA\EntAuth\Crypt;


class PageController extends Controller {
    private $userSession;
    private $userManager;
    private $urlGenerator;
    private $logger;
    private $Csrfman;
    private $AuthServices;
    private $ExternalIds;
    private $Crypt;
	
	public function __construct($AppName,
	    IRequest $request,
	    IUserSession $userSession,
	    IUserManager $userManager,
	    IURLGenerator $urlGenerator,
	    ILogger $logger,
	    CsrfTokenManager $Csrfman,
	    AuthServices $AuthServices,
	    ExternalIds $ExternalIds,
	    Crypt $Crypt) {
		parent::__construct($AppName, $request);
		$this->request = $request;
		$this->userSession = $userSession;
		$this->userManager = $userManager;
		$this->urlGenerator = $urlGenerator;
		$this->logger = $logger;
		$this->Csrfman = $Csrfman;
		$this->AuthServices = $AuthServices;
		$this->ExternalIds = $ExternalIds;
		$this->Crypt = $Crypt;
	}

	/**
	 * @NoAdminRequired
	 * @PublicPage
	 * @NoCSRFRequired
	 */
	public function index() {
	    /*
	    $crpt = $this->Crypt->seal('7c7a2376-93c8-4b40-8d22-532eae2f407c');
	    $decrpt = $this->Crypt->open($crpt);
	    $tk = $this->Csrfman->getToken();
	    */
	    $l = [];
	    foreach ($this->AuthServices->listProviders() as $prov) {
	        $l[] = [
	            'name' => $prov['name'],
	            'url' => $this->urlGenerator->linkToRoute('entauth.page.login', ['srv' => $prov['srv']]),
	        ];
	    }
	    
	    $parameters = [
	        'providers' => $l,
	        'backUrl' => $this->urlGenerator->linkToRoute('core.login.showLoginForm'),
	        
	    ];
	    
	    return new TemplateResponse(
	        $this->appName, 'index', $parameters, 'guest'
	        );
	}
	
	/**
	 * @NoAdminRequired
	 * @UseSession
	 * @PublicPage
	 * @NoCSRFRequired
	 * 
	 * @param string $srv auth/identity provider
	 * @param string $code
	 * @param string $state
	 */
	public function login($srv, $code, $state) {
	    if($this->userSession->isLoggedIn()) $this->userSession->logout();
	    //Get provider for specified auth/identity provider
	    $prov = $this->AuthServices->getProvider($srv);
	    if(!$prov) return new NotFoundResponse();
	    $myUrl = $this->urlGenerator->linkToRouteAbsolute('entauth.page.login', ['srv' => $prov->getSrv()]);
	    
	    $prov->setRedirectUri($myUrl);
	    if($code || $state) {
	        //we are back from auth provider
	        if((!$code) || (!$state)) return new NotFoundResponse();
	        //validate CSRF
	        $csrf = new CsrfToken($this->Crypt->open($state));
	        if(!$this->Csrfman->isTokenValid($csrf)) throw new \Exception('CSRF check failed');
	        //get token from auth provider
	        $tk = $prov->getToken($code);
	        if(!$tk)  throw new \Exception('Could not retrieve token');
	        //get user data from identity  provider
	        $userData = $prov->getUserData($tk);
	        if((!$userData) || (!$userData->userId)) throw new \Exception('Could not retrieve user data');
	        //Search internal user that is linked to this external one.
	        $uid = $this->ExternalIds->GetUser($prov->getDbId(), $userData->userId);
	        if($uid) {
	            $user = $this->userManager->get($uid);
	            if(!$user) throw new \Exception("User {$uid} does not exist");
	            //Internal user found, log him in and redirect to home page
	            $this->userSession->completeLogin($user, ['loginName' => $uid, 'password' => 'SSO login']);
	            $this->userSession->createSessionToken($this->request, $uid, $uid);
	            return new RedirectResponse(\OC_Util::getDefaultPageUrl());
	        } else {
	            //Internal user not found,
	            //Display login form to request internal credencials
	            return $this->createLoginFormResponse(null, $prov, $tk, $userData->ExtractDigest());
	        }
	    } else {
	        //Redirect to auth provider
	        $state = $this->Crypt->seal($this->Csrfman->getToken()->getEncryptedValue());
    	    $url = $prov->getLoginUrl($state);
    	    return new RedirectResponse($url);
	    }
	}
	
	/**
	 * @NoAdminRequired
	 * @UseSession
	 * @PublicPage
	 * @BruteForceProtection(action=login)
	 */
	public function associate($srv, $tk, $user, $password) {
	    if(!is_string($user)) {
	        throw new \InvalidArgumentException('Username must be string');
	    }
	    if($this->userSession->isLoggedIn()) {
	        $this->userSession->logout();
	        throw new \Exception('An already logged in user was found');
	    }
	    $tk = $this->Crypt->open($tk);
	    if(!$tk) throw new \Exception('Auth token expired');
	    
	    //validate provided creds
	    
	    if ($this->userManager instanceof PublicEmitter) {
	        $this->userManager->emit('\OC\User', 'preLogin', array($user, $password));
	    }
	    
	    $originalUser = $user;
	    
	    $userObj = $this->userManager->get($user);
	    
	    if ($userObj !== null && $userObj->isEnabled() === false) {
	        $this->logger->warning('Login failed: \''. $user . '\' disabled' .
	            ' (Remote IP: \''. $this->request->getRemoteAddress(). '\')',
	            ['app' => 'core']);
	        return $this->createLoginFormResponse2($user, $originalUser, $srv, $tk,
	            LoginController::LOGIN_MSG_USERDISABLED);
	    }

	    // TODO: Add all the insane error handling
	    /* @var $loginResult IUser */
	    $loginResult = $this->userManager->checkPasswordNoLogging($user, $password);
	    if ($loginResult === false) {
	        $users = $this->userManager->getByEmail($user);
	        // we only allow login by email if unique
	        if (count($users) === 1) {
	            $previousUser = $user;
	            $user = $users[0]->getUID();
	            if($user !== $previousUser) {
	                $loginResult = $this->userManager->checkPassword($user, $password);
	            }
	        }
	    }
	    
	    if ($loginResult === false) {
	        $this->logger->warning('Login failed: \''. $user .
	            '\' (Remote IP: \''. $this->request->getRemoteAddress(). '\')',
	            ['app' => 'core']);
	        return $this->createLoginFormResponse2($user, $originalUser, $srv, $tk,
	            LoginController::LOGIN_MSG_INVALIDPASSWORD);
	    }
	    
	    //get user data from identity  provider
	    $prov = $this->AuthServices->getProvider($srv);
	    if(!$prov) return new NotFoundResponse();
	    $userData = $prov->getUserData($tk);
	    if((!$userData) || (!$userData->userId)) throw new \Exception('Auth token expired');
	    
	    //link internal user to external user
	    $this->ExternalIds->addUser($prov->getDbId(), $userData->userId, $loginResult->getUID());
	    
	    //login user
	    // TODO: remove password checks from above and let the user session handle failures
	    // requires https://github.com/owncloud/core/pull/24616
	    $this->userSession->completeLogin($loginResult, ['loginName' => $user, 'password' => $password]);
	    $this->userSession->createSessionToken($this->request, $loginResult->getUID(), $user, $password);
	    
	    
	    //display association success message page
	    $parameters = [
	        'backUrl' => $this->urlGenerator->linkToRoute('core.login.showLoginForm'),
	    ];
	    return new TemplateResponse($this->appName, 'done', $parameters, 'guest');
	    
	}
	
	private function createLoginFormResponse2(
	    $user, $originalUser, $srv, $tk, string $loginMessage = null) {
	        //get user data from identity  provider
	        $prov = $this->AuthServices->getProvider($srv);
	        if(!$prov) return new NotFoundResponse();
	        $userData = $prov->getUserData($tk);
	        if((!$userData) || (!$userData->userId)) throw new \Exception('Auth token expired');
	        
	        $loginName = null;
	        if($user !== null && $user !== '') $loginName = $originalUser;

	        return $this->createLoginFormResponse($loginName, $prov, $tk, $userData->ExtractDigest(), $loginMessage);
	}

	private function createLoginFormResponse(
	    $loginName, $prov, $tk, $digest, string $loginMessage = null) {
	        $actionUrl = $this->urlGenerator->linkToRoute('entauth.page.associate', ['srv' => $prov->getSrv()]);
	        $parameters = [
	            'tk' => $this->Crypt->seal($tk),
	            'user' => $digest,
	            'prov' => $prov->getName(),
	            'actionUrl' => $actionUrl,
	            'l'  => \OCP\Util::getL10N('core'),
	            'backUrl' => $this->urlGenerator->linkToRoute('core.login.showLoginForm'),
	        ];
	        if ($loginMessage) $parameters[$loginMessage] = true;
	        if($loginName !== null && $loginName !== '') $parameters['loginName'] = $loginName;
	        
	        return new TemplateResponse(
	            $this->appName, 'login', $parameters, 'guest'
	            );
	}
}
