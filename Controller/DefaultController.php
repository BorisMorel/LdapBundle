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

use Symfony\Bundle\FrameworkBundle\Controller\Controller,
  Symfony\Component\Security\Core\SecurityContext;

class DefaultController extends Controller
{
  public function loginAction()
  {
    if ($this->get('request')->attributes->has(SecurityContext::AUTHENTICATION_ERROR)) {
      $error = $this->get('request')->attributes->get(SecurityContext::AUTHENTICATION_ERROR);
    }else {
      $error = $this->get('request')->getSession()->get(SecurityContext::AUTHENTICATION_ERROR);
    }
        
    return $this->render('IMAGLdapBundle:Default:login.html.twig', array(
      'last_username' => $this->get('request')->getSession()->get(SecurityContext::LAST_USERNAME),
      'error'         => $error
    ));
  }
}
