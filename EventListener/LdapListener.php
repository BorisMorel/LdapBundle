<?php

namespace IMAG\LdapBundle\EventListener;

use Symfony\Component\EventDispatcher\EventDispatcherInterface,
    Symfony\Component\HttpFoundation\Request,
    Psr\Log\LoggerInterface,
    Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface,
    Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken,
    Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException,
    Symfony\Component\Security\Http\Authentication\AuthenticationFailureHandlerInterface,
    Symfony\Component\Security\Http\Authentication\AuthenticationSuccessHandlerInterface,
    Symfony\Component\Security\Http\Firewall\AbstractAuthenticationListener,
    Symfony\Component\Security\Http\HttpUtils,
    Symfony\Component\Security\Http\Session\SessionAuthenticationStrategyInterface
;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Security;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;

class LdapListener extends AbstractAuthenticationListener
{
    public function __construct(TokenStorageInterface $securityContext,
                                AuthenticationManagerInterface $authenticationManager,
                                SessionAuthenticationStrategyInterface $sessionStrategy,
                                HttpUtils $httpUtils,
                                $providerKey,
                                AuthenticationSuccessHandlerInterface $successHandler = null,
                                AuthenticationFailureHandlerInterface $failureHandler = null,
                                array $options = array(),
                                LoggerInterface $logger = null,
                                EventDispatcherInterface $dispatcher = null,
                                CsrfTokenManagerInterface $csrfProvider = null)
    {
        parent::__construct(
            $securityContext,
            $authenticationManager,
            $sessionStrategy,
            $httpUtils,
            $providerKey,
            $successHandler,
            $failureHandler,
            array_merge(array(
                'username_parameter' => '_username',
                'password_parameter' => '_password',
                'csrf_parameter'     => '_csrf_token',
                'intention'          => 'ldap_authenticate',
                'post_only'          => true,
            ), $options),
            $logger,
            $dispatcher
        );
        
        $this->csrfProvider = $csrfProvider;
    }

    /**
     * {@inheritdoc}
     */
    protected function requiresAuthentication(Request $request)
    {
        if ($this->options['post_only'] && !$request->isMethod('post')) {
            return false;
        }

        return parent::requiresAuthentication($request);
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
            $csrfToken = new CsrfToken($this->options['intention'], $request->get($this->options['csrf_parameter'], null, true));

            if (false === $this->csrfProvider->isTokenValid($csrfToken)) {
                throw new InvalidCsrfTokenException('Invalid CSRF token.');
            }
        }

        $username = trim($request->get($this->options['username_parameter'], null, true));
        $password = $request->get($this->options['password_parameter'], null, true);

        $request->getSession()->set(Security::LAST_USERNAME, $username);

        return $this->authenticationManager->authenticate(new UsernamePasswordToken($username, $password, $this->providerKey));
    }
}
