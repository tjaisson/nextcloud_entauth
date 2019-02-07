<?php
namespace OCA\EntcoreAuth\Controller;

use OCP\IRequest;
use OCP\AppFramework\Http\Template\PublicTemplateResponse;
use OCP\AppFramework\Http\DataResponse;
use OCP\AppFramework\Controller;
use OCA\EntcoreAuth\Crypt;

class PageController extends Controller {
	private $userId;
	private $Crypt;
	
	public function __construct($AppName,
	    IRequest $request,
	    $UserId,
	    Crypt $Crypt) {
		parent::__construct($AppName, $request);
		$this->userId = $UserId;
		$this->Crypt = $Crypt;
	}

	/**
	 * @NoAdminRequired
	 * @PublicPage
	 * @NoCSRFRequired
	 */
	public function index() {
	    $crpt = $this->Crypt->seal('7c7a2376-93c8-4b40-8d22-532eae2f407c');
	    $decrpt = $this->Crypt->open($crpt);
	    $template = new PublicTemplateResponse($this->appName, 'index', ['crpt' => $crpt, 'decrpt' => $decrpt]);
	    $template->setHeaderTitle('Authentification ENT');
	    $template->setHeaderDetails('Associer un compte');
	    return $template;
	}

}
