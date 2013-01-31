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
        $hideUserNotFoundExceptions,
        $anonSearchAllowed
        ;

    /**
     * Constructor
     *
     * Please note that $hideUserNotFoundExceptions is true by default in order
     * to prevent a possible brute-force attack.
     *
     * @param UserProviderInterface    $userProvider
     * @param LdapManagerUserInterface $ldapManager
     * @param EventDispatcherInterface $dispatcher
     * @param string                   $providerKey
     * @param Boolean                  $hideUserNotFoundExceptions
     * @param Boolean                  $anonSearchAllowed
     */
    public function __construct(
        UserProviderInterface $userProvider,
        LdapManagerUserInterface $ldapManager,
        EventDispatcherInterface $dispatcher = null,
        $providerKey,
        $hideUserNotFoundExceptions = true,
        $anonSearchAllowed = true
    )
    {
        $this->userProvider = $userProvider;
        $this->ldapManager = $ldapManager;
        $this->dispatcher = $dispatcher;
        $this->providerKey = $providerKey;
        $this->hideUserNotFoundExceptions = $hideUserNotFoundExceptions;
        $this->anonSearchAllowed = $anonSearchAllowed;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('Unsupported token');
        }

        if ($this->anonSearchAllowed) {
            try {
                $user = $this->userProvider
                    ->loadUserByUsername($token->getUsername());
            } catch (UsernameNotFoundException $userNotFoundException) {
                if (!$this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials', 0, $userNotFoundException);
                }
                throw $userNotFoundException;
            }
        } else {
            $user = new LdapUser();
            $user->setUsername($token->getUsername());
        }

        if (null !== $this->dispatcher && $user instanceof LdapUser) {
            $userEvent = new LdapUserEvent($user);
            try {
                $this->dispatcher->dispatch(LdapEvents::PRE_BIND, $userEvent);
            } catch(\Exception $expt) {
                if (!$this->hideUserNotFoundExceptions) {
                    throw new BadCredentialsException('Bad credentials', 0, $expt);
                }

                throw $expt;
            }
        }

        if ($this->bind($user, $token)) {
            if (!$this->anonSearchAllowed) {
                $user = $this->userProvider->loadUserByUsername($token->getUsername());
            }
            $ldapToken = new LdapToken($user, '', $this->providerKey, $user->getRoles());
            $ldapToken->setAuthenticated(true);
            $ldapToken->setAttributes($token->getAttributes());

            return $ldapToken;
        }

        throw new AuthenticationException('The LDAP authentication failed.');
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
        $this->ldapManager
            ->setUsername($user->getUsername())
            ->setPassword($token->getCredentials());

        if ($this->anonSearchAllowed) {
            return (bool)$this->ldapManager->auth();
        } else {
            return (bool)$this->ldapManager->authNoAnonSearch();
        }
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
