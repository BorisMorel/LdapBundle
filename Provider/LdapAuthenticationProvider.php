<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;

use IMAG\LdapBundle\Authentication\Token\LdapToken;
use IMAG\LdapBundle\Manager\LdapManagerUserInterface;
use IMAG\LdapBundle\Event\LdapUserEvent;
use IMAG\LdapBundle\Event\LdapEvents;
use IMAG\LdapBundle\User\LdapUser;


class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
    private
        $userProvider,
        $ldapManager,
        $dispatcher,
        $providerKey,
        $hideUserNotFoundExceptions
        ;

    /**
     * Constructor
     *
     * Please note that $hideUserNotFoundExceptions is true by default in order
     * to prevent a possible brute-force attack.
     *
     * @param UserProviderInterface    $userProvider
     * @param LdapManagerUserInterface $ldapManager
     * @param string                   $providerKey
     * @param Boolean                  $hideUserNotFoundExceptions
     */
    public function __construct(
        UserProviderInterface $userProvider,
        LdapManagerUserInterface $ldapManager,
        EventDispatcherInterface $dispatcher = null,
        $providerKey,
        $hideUserNotFoundExceptions = true
    )
    {
        $this->userProvider = $userProvider;
        $this->ldapManager = $ldapManager;
        $this->dispatcher = $dispatcher;
        $this->providerKey = $providerKey;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('Unsupported token');
        }

        try {
            $user = $this->userProvider
                ->loadUserByUsername($token->getUsername());
        } catch (UsernameNotFoundException $userNotFoundException) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $userNotFoundException);
            }

            throw $userNotFoundException;
        }
        
        try {
            $this->dispatch(LdapEvents::PRE_BIND, $user);
            $this->bind($user, $token);
            $event = $this->dispatch(LdapEvents::POST_BIND, $user);
        } catch (BadCredentialsException $e) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $e);
            }

            throw $e;
        }
        
        $ldapToken = new LdapToken($event->getUser(), '', $this->providerKey, $user->getRoles());
        $ldapToken->setAuthenticated(true);
        $ldapToken->setAttributes($token->getAttributes());

        return $ldapToken;
    }

    private function dispatch($event, LdapUser $user)
    {
        if (null !== $this->dispatcher) {
            $userEvent = new LdapUserEvent($user);
            try {
                $this->dispatcher->dispatch($event, $userEvent);

                return $userEvent;
            } catch (\Exception $e) {
                throw new BadCredentialsException($e->getMessage(), 0, $e);
            }
        }
    }

    /**
     * Authenticate the user with LDAP bind.
     *
     * @param UserInterface  $user
     * @param TokenInterface $token
     *
     * @return boolean
     */
    private function bind(UserInterface $user, TokenInterface $token)
    {
        $res = $this->ldapManager
            ->setUsername($user->getUsername())
            ->setPassword($token->getCredentials())
            ->auth();

        if (false === $res) {
            throw new BadCredentialsException('Ldap bind failed');
        }

        return true;
    }

    /**
     * Check whether this provider supports the given token.
     *
     * @param TokenInterface $token
     *
     * @return boolean
     */
    public function supports(TokenInterface $token)
    {
        return ( $token instanceof LdapToken
                 || $token instanceof UsernamePasswordToken ) 
            && $token->getProviderKey() === $this->providerKey;
    }

}
