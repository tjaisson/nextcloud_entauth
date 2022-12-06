<?php
declare(strict_types=1);
// SPDX-FileCopyrightText: Thomas Jaisson <thomas.jaisson@ac-paris.fr>
// SPDX-License-Identifier: AGPL-3.0-or-later

namespace OCA\EntAuth\Controller;

use OC\Authentication\Login\Chain;
use OC\Authentication\Login\LoginData;
use OCP\AppFramework\Controller;
use OCP\AppFramework\Http\TemplateResponse;
use OCP\IRequest;
use OC\Core\Controller\LoginController;
use OCP\AppFramework\Http\NotFoundResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OC\User\Session;
use OCP\IUserManager;
use OCP\IURLGenerator;

use OCA\EntAuth\AppInfo\Application;
use OCA\EntAuth\AuthServices;
use OCA\EntAuth\SsoChain;
use OCA\EntAuth\ExternalIds;
use OCA\EntAuth\Security\TokenServiceInterface;

class PageController extends Controller {
	const SRV_SUB = 'srv';
	const TK_SUB = 'tk';
	const TTL = 600;
	/** @var Chain */
	private $loginChain;

	/** @var \OC\User\Session $userSession */
    private $userSession;
	/** @var \OCP\IUserManager $userManager */
    private $userManager;
	/** @var \OCP\IURLGenerator $urlGenerator */
    private $urlGenerator;
	/** @var \OCA\EntAuth\AuthServices $AuthServices */
    private $AuthServices;
	/** @var \OCA\EntAuth\SsoChain $ssoChain */
    private $ssoChain;
	/** @var \OCA\EntAuth\ExternalIds $ExternalIds */
    private $ExternalIds;
	/** @var \OCA\EntAuth\Security\TokenServiceInterface $tkService */
	private $tkService;
	public function __construct(
		IRequest $request,
		Session $userSession,
	    IUserManager $userManager,
	    IURLGenerator $urlGenerator,
		Chain $chain,
	    AuthServices $AuthServices,
	    SsoChain $ssoChain,
	    ExternalIds $ExternalIds,
		TokenServiceInterface $tkService) {
		parent::__construct(Application::APP_ID, $request);
		$this->userSession = $userSession;
		$this->userManager = $userManager;
		$this->urlGenerator = $urlGenerator;
		$this->loginChain = $chain;
		$this->AuthServices = $AuthServices;
		$this->ssoChain = $ssoChain;
		$this->ExternalIds = $ExternalIds;
		$this->tkService = $tkService;
	}

	/**
	 * @NoAdminRequired
	 * @PublicPage
	 * @NoCSRFRequired
	 */
	public function index(): TemplateResponse {
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
	 * @param string $tk
	 */
	public function login($srv, $code, $state, $tk) {
	    //Get provider for specified auth/identity provider
	    $prov = $this->AuthServices->getProvider($srv);
	    if(!$prov) return new NotFoundResponse();
	    $myUrl = $this->urlGenerator->linkToRouteAbsolute('entauth.page.login', ['srv' => $prov->getSrv()]);
	    $prov->setRedirectUri($myUrl);
		if (empty($code) && empty($state) && empty($tk)) {
	        //Redirect to auth provider
			$builder = $this->tkService->createBuilder();
			$builder->withData($srv)->withTTL(self::TTL)->withSubject(self::SRV_SUB);
			$state = $builder->toString();			
    	    $url = $prov->getLoginUrl($state);
    	    return new RedirectResponse($url);
		}

		if (! empty($tk)) {
			if($this->userSession->isLoggedIn()) throw new \Exception('Erreur de process.');
			if((! empty($code)) || (! empty($state))) throw new \Exception('Erreur de process.');
			$validator = $this->tkService->createValidator();
			$validator->withToken($tk)->withSubject(self::TK_SUB);
	        if(!$validator->validate()) throw new \Exception('Connexion expirée.');
			$tk = $validator->getData();
	        //get user data from identity  provider
	        $userData = $prov->getUserData($tk);
	        if((!$userData) || (empty($userData->userId))) throw new \Exception('Could not retrieve user data');
		} else {
			if ((empty($code)) || (empty($state))) throw new \Exception('Erreur de process.');
	        //validate STATE
			$validator = $this->tkService->createValidator();
			$validator->withToken($state)->withSubject(self::SRV_SUB);
	        if(!$validator->validate()) throw new \Exception('CSRF check failed');
	        if($validator->getData() !== $srv) throw new \Exception('CSRF check failed');
	        //get token from auth provider
	        $tk = $prov->getToken($code);
	        if(!$tk) throw new \Exception('Could not retrieve token');
	        //get user data from identity  provider
	        $userData = $prov->getUserData($tk);
	        if((!$userData) || (empty($userData->userId))) throw new \Exception('Could not retrieve user data');
		}
		//Search internal user that is linked to this external one.
		$uid = $this->ExternalIds->GetUser($prov->getDbId(), $userData->userId);
		if($uid) {
			if ($this->userSession->isLoggedIn()) {
				if ($this->userSession->getUser()->getUID() === $uid) {
					// L'utilisateur est déjà connecté
					$this->ExternalIds->TouchUser($prov->getDbId(), $userData->userId);
					return new RedirectResponse(\OC_Util::getDefaultPageUrl());
				} else {
					// Changement d'utilisateur
					$this->userSession->logout();
					$builder = $this->tkService->createBuilder();
					$builder->withEncription()->withNonce()->withSubject(self::TK_SUB)
					->withData($tk)->withTTL(10);
					return new RedirectResponse($this->urlGenerator->linkToRoute(
						'entauth.page.login',
						['srv' => $prov->getSrv(), 'tk' => $builder->toString()]
					));
				}
			}
			$user = $this->userManager->get($uid);
			if(!$user) throw new \Exception("User {$uid} does not exist");
			//Internal user found, log him in and redirect to home page
			$data = new LoginData(
				$this->request,
				$uid,
				'SSO login'
			);
			$result = $this->ssoChain->process($data);
			if (!$result->isSuccess()) throw new \Exception("Connexion impossible.");

			$this->userSession->completeLogin($user, ['loginName' => $uid, 'password' => 'SSO login']);
			$this->userSession->createSessionToken($this->request, $uid, $uid);
			$this->ExternalIds->TouchUser($prov->getDbId(), $userData->userId);
			return new RedirectResponse(\OC_Util::getDefaultPageUrl());
		} else {
			//Internal user not found,
			//Display login form to request internal credencials
			if ($this->userSession->isLoggedIn()) {
				$this->userSession->logout();
				$builder = $this->tkService->createBuilder();
				$builder->withEncription()->withNonce()->withSubject(self::TK_SUB)
				->withData($tk)->withTTL(10);
				return new RedirectResponse($this->urlGenerator->linkToRoute(
					'entauth.page.login',
					['srv' => $prov->getSrv(), 'tk' => $builder->toString()]
				));
			} else {
				return $this->createLoginFormResponse(
					null,
					$prov,
					$tk,
					$userData->ExtractDigest()
				);
			}
		}
	}
	
	/**
	 * @NoAdminRequired
	 * @UseSession
	 * @PublicPage
	 * @BruteForceProtection(action=login)
	 */
	public function associate($srv, $tk, $user, $password)
	{
		if($this->userSession->isLoggedIn()) {
			$this->userSession->logout();
			throw new \Exception('An already logged in user was found');
		}
		if (!$this->request->passesCSRFCheck()) {
			throw new \Exception('An error occured');
		}
		
		$validator = $this->tkService->createValidator();
		$validator->withToken($tk)->withSubject(self::TK_SUB);
		if(!$validator->validate()) throw new \Exception('Auth token expired');
		$tk = $validator->getData();
		//get user data from identity  provider
		$prov = $this->AuthServices->getProvider($srv);
		if(!$prov) return new NotFoundResponse();
		$userData = $prov->getUserData($tk);
		if((!$userData) || (!$userData->userId)) throw new \Exception('Auth token expired');
		
		$data = new LoginData(
			$this->request,
			trim($user),
			$password
		);
		$result = $this->loginChain->process($data);

	    if (!$result->isSuccess()) {
	        return $this->createLoginFormResponse(
				$user,
				$prov,
				$tk,
				$userData->ExtractDigest(),
				LoginController::LOGIN_MSG_INVALIDPASSWORD,
				$validator->getExpiration()
			);
	    }
	    
	    //link internal user to external user
	    $this->ExternalIds->addUser($prov->getDbId(), $userData->userId, $data->getUser()->getUID());
	    
	    //display association success message page
	    return new TemplateResponse(
			$this->appName,
			'done',
			['backUrl' => \OC_Util::getDefaultPageUrl()],
			'guest'
		);
	}
	
	private function createLoginFormResponse(
	    $loginName,
		$prov,
		$tk,
		$digest,
		$loginMessage = null,
		$expir = null)
	{
		$builder = $this->tkService->createBuilder();
		$builder->withData($tk)
		->withSubject(self::TK_SUB)
		->withEncription()
		->withNonce();
		if (empty($expir)) {
			$builder->withTTL(self::TTL);
		} else {
			$builder->withExpiration($expir);
		}
		$stk = $builder->toString();
		$actionUrl = $this->urlGenerator->linkToRoute('entauth.page.associate', ['srv' => $prov->getSrv()]);
		$parameters = [
			'tk' => $stk,
			'user' => $digest,
			'prov' => $prov->getName(),
			'actionUrl' => $actionUrl,
			'l'  => \OCP\Util::getL10N('core'),
			'backUrl' => $this->urlGenerator->linkToRoute('core.login.showLoginForm'),
		];
		if (! empty($loginMessage)) $parameters[$loginMessage] = true;
		if (! empty($loginName)) $parameters['loginName'] = $loginName;

		return new TemplateResponse(
			$this->appName,
			'login',
			$parameters,
			'guest'
		);
	}
}
