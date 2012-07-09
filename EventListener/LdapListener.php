<?php

namespace IMAG\LdapBundle\EventListener;

use Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener,
  Symfony\Component\Security\Core\SecurityContextInterface,
  Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface,
  Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface,
  Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface,
  Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface,
  Symfony\Component\HttpKernel\Log\LoggerInterface,
  Symfony\Component\EventDispatcher\EventDispatcherInterface,
  Symfony\Component\Form\Extension\Csrf\CsrfProvider\CsrfProviderInterface,
  Symfony\Component\HttpFoundation\Request,
  Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException,
  IMAG\LdapBundle\Authentication\Token\LdapToken,
  Symfony\Component\Security\Http\HttpUtils
  ;

class LdapListener extends AbstractAuthenticationListener
{
  public function __construct(SecurityContextInterface $securityContext,
                              AuthenticationManagerInterface $authenticationManager,
                              SessionAuthenticationStrategyInterface $sessionStrategy,
                              HttpUtils $httpUtils,
                              $providerKey,
                              AuthenticationSuccessHandlerInterface $successHandler = null,
                              AuthenticationFailureHandlerInterface $failureHandler = null,
                              array $options = array(),
                              LoggerInterface $logger = null,
                              EventDispatcherInterface $dispatcher = null,
                              CsrfProviderInterface $csrfProvider = null)
  {
    parent::__construct($securityContext, $authenticationManager, $sessionStrategy, $httpUtils, $providerKey, $options, $successHandler, $failureHandler, $logger, $dispatcher);

    $this->csrfProvider = $csrfProvider;
  }

  public function attemptAuthentication(Request $request)
  {
    if ($this->options['post_only'] && 'post' !== strtolower($request->getMethod())) {
      if (null !== $this->logger) {
        $this->logger->debug(sprintf('Authentication method not supported: %s.', $request->getMethod()));
      }

      return null;
    }

    if (null !== $this->csrfProvider) {
      $csrfToken = $request->get($this->options['csrf_parameter'], null, true);

      if (false === $this->csrfProvider->isCsrfTokenValid($this->options['intention'], $csrfToken)) {
        throw new InvalidCsrfTokenException('Invalid CSRF token.');
      }
    }

    $username = trim($request->get($this->options['username_parameter'], null, true));
    $password = $request->get($this->options['password_parameter'], null, true);

    $request->getSession()->set(SecurityContextInterface::LAST_USERNAME, $username);

    return $this->authenticationManager->authenticate(new LdapToken($username, $password));
  }


}