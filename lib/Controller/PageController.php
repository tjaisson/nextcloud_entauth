<?php
namespace OCA\EntcoreAuth\Controller;

use OCP\IRequest;
use OCP\IUserSession;
use OCP\AppFramework\Http\Template\PublicTemplateResponse;
use OCP\AppFramework\Http\NotFoundResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Controller;
use OCA\EntcoreAuth\Crypt;
use OCA\EntcoreAuth\Oauth;
use OC\Security\CSRF\CsrfTokenManager;


class PageController extends Controller {
	private $userId;
	private $Crypt;
	private $Oauth;
	private $Csrfman;
	private $userSession;
	private $request;
	
	public function __construct($AppName,
	    IRequest $request,
	    IUserSession $userSession,
	    $UserId,
	    Crypt $Crypt,
	    Oauth $Oauth,
	    CsrfTokenManager $Csrfman) {
		parent::__construct($AppName, $request);
		$this->userId = $UserId;
		$this->Crypt = $Crypt;
		$this->Oauth = $Oauth;
		$this->Csrfman = $Csrfman;
		$this->userSession = $userSession;
		$this->request = $request;
	}

	/**
	 * @NoAdminRequired
	 * @PublicPage
	 * @NoCSRFRequired
	 */
	public function index() {
	    $crpt = $this->Crypt->seal('7c7a2376-93c8-4b40-8d22-532eae2f407c');
	    $decrpt = $this->Crypt->open($crpt);
	    $tk = $this->Csrfman->getToken();
	    
	    $template = new PublicTemplateResponse($this->appName, 'index',
	        ['crpt' => $crpt,
	         'decrpt' => $decrpt,
	            'tke' => $tk->getEncryptedValue(),
	            'tk' => \base64_encode($tk->getDecryptedValue()),
	        ]);
	    $template->setHeaderTitle('Authentification ENT');
	    $template->setHeaderDetails('Associer un compte');
	    return $template;
	}
	
	/**
	 * @NoAdminRequired
	 * @PublicPage
	 * @NoCSRFRequired
	 * 
	 * @param string $srv
	 * @param string $code
	 * @param string $state
	 */
	public function login($srv, $code, $state) {
	    if($this->userSession->isLoggedIn()) $this->userSession->logout();
	    $con = $this->Oauth->getConnector($srv);
	    if(!$con) return new NotFoundResponse();
	    $con->setRedirectUri();
	    if($code || $state) {
	        if((!$code) || (!$state)) return new NotFoundResponse();
	        //validate $state
	        $tk = $con->getToken($code);
	        if(!$tk) return new NotFoundResponse();
	        $userData = $con->getUserData($tk);
	        if(!$userData) return new NotFoundResponse();
	        if(!$userData->userId) return new NotFoundResponse();
	        
	    }
	    
	    
	    return new RedirectResponse($con->getLoginUrl($state));
	    
	}
	
	/**
	 * @NoAdminRequired
	 * @PublicPage
	 * @BruteForceProtection(action=login)
	 */
	public function associate($srv) {
	    if($this->userSession->isLoggedIn()) {
	        $this->userSession->logout();
	        return new NotFoundResponse();
	    }
	}
	
}
