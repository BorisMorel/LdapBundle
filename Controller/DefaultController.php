<?php
/*
 * This file is part of the Symfony framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace IMAG\LdapBundle\Controller;

use Symfony\Bundle\FrameworkBundle\Controller\Controller;

use Symfony\Component\Security\Core\Security;

class DefaultController extends Controller
{
    public function loginAction()
    {
        $error = $this->getAuthenticationError();

        return $this->render('@IMAGLdapBundle/Default/login.html.twig', array(
            'last_username' => $this->get('request_stack')->getCurrentRequest()->get(Security::LAST_USERNAME),
            'error'         => $error,
            'token'         => $this->generateToken(),
        ));
    }

    protected function getAuthenticationError()
    {
        if ($this->get('request_stack')->getCurrentRequest()->attributes->has(Security::AUTHENTICATION_ERROR)) {
            return $this->get('request_stack')->getCurrentRequest()->attributes->get(Security::AUTHENTICATION_ERROR);
        }

        return $this->get('request_stack')->getCurrentRequest()->getSession()->get(Security::AUTHENTICATION_ERROR);
    }

    protected function generateToken()
    {
        $token = $this->get('security.csrf.token_manager')
                      ->getToken('authenticate');

        return $token;
    }
}
