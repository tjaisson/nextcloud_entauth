<?php
namespace OCA\EntcoreAuth\Controller;

use OCP\IRequest;
use OCP\IUserSession;
use OCP\AppFramework\Http\Template\PublicTemplateResponse;
use OCP\AppFramework\Http\NotFoundResponse;
use OCP\AppFramework\Http\RedirectResponse;
use OCP\AppFramework\Controller;
use OCA\EntcoreAuth\Crypt;
use OCA\EntcoreAuth\AuthServices;
use OCA\EntcoreAuth\ExternalIds;
use OC\Security\CSRF\CsrfToken;
use OC\Security\CSRF\CsrfTokenManager;


class PageController extends Controller {
	private $Crypt;
	private $AuthServices;
	private $Csrfman;
	private $userSession;
	private $request;
	private $ExternalIds;
	
	public function __construct($AppName,
	    IRequest $request,
	    IUserSession $userSession,
	    Crypt $Crypt,
	    AuthServices $AuthServices,
	    ExternalIds $ExternalIds,
	    CsrfTokenManager $Csrfman) {
		parent::__construct($AppName, $request);
		$this->Crypt = $Crypt;
		$this->AuthServices = $AuthServices;
		$this->ExternalIds = $ExternalIds;
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
	    $con = $this->AuthServices->getConnector($srv);
	    if(!$con) return new NotFoundResponse();
	    $con->setRedirectUri();
	    if($code || $state) {
	        //we are back from auth provider
	        if((!$code) || (!$state)) return new NotFoundResponse();
	        //validate CSRF
	        $csrf = $this->Crypt->open($state);
	        $csrf = new CsrfToken($csrf);
	        if(!$this->Csrfman->isTokenValid($csrf)) return new NotFoundResponse();
	        //get token from auth provider
	        $tk = $con->getToken($code);
	        if(!$tk) return new NotFoundResponse();
	        //get user data from identity  provider
	        $userData = $con->getUserData($tk);
	        if((!$userData) || (!$userData->userId)) return new NotFoundResponse();
	        //Search internal user that is linked to this external one.
	        if($this->ExternalIds->GetUser($userData->userId)) {
	            //Internal user found, log him in and redirect to home page
	            
	            
	        } else {
	            //Internal user not found,
	            //Display form to request internal credencials
	            $template = new PublicTemplateResponse($this->appName, 'login',
	                [
	                    'tk' => $this->Crypt->seal($tk),
	                    'user' => $userData->ExtractDigest(),
	                    'postUrl' => '',
	                ]);
	            $template->setHeaderTitle('Authentification ENT');
	            return $template;
	        }
	    } else {
	        //Redirect to auth provider
    	    $state = $this->Crypt->seal($this->Csrfman->getToken());
    	    return new RedirectResponse($con->getLoginUrl($state));
	    }
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
