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
     * @param EventDispatcherInterface $dispatcher
     * @param string                   $providerKey
     * @param Boolean                  $hideUserNotFoundExceptions
     */
    public function __construct(
        UserProviderInterface $userProvider,
        AuthenticationProviderInterface $daoAuthenticationProvider,
        LdapManagerUserInterface $ldapManager,
        EventDispatcherInterface $dispatcher = null,
        $providerKey,
        $hideUserNotFoundExceptions = true
    )
    {
        $this->userProvider = $userProvider;
        $this->daoAuthenticationProvider = $daoAuthenticationProvider;
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

        if ($user instanceof LdapUser) {
            if (null !== $this->dispatcher) {
                $userEvent = new LdapUserEvent($user);
                try {
                    $this->dispatcher->dispatch(LdapEvents::PRE_BIND, $userEvent);
                } catch (\Exception $expt) {
                    if ($this->hideUserNotFoundExceptions) {
                        throw new BadCredentialsException('Bad credentials', 0, $expt);
                    }

                    throw $expt;
                }
            }

            if ($this->bind($user, $token)) {
                if (false === $user->getDn()) {
                    $user = $this->reloadUser($user);
                }

                $ldapToken = new LdapToken($user, $this->providerKey, $user->getRoles());
                $ldapToken->setAuthenticated(true);
                $ldapToken->setAttributes($token->getAttributes());

                return $ldapToken;
            }

            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials');
            } else {
                throw new AuthenticationException('The LDAP authentication failed.');
            }
        }

        if ($user instanceof UserInterface) {
            return $this->daoAuthenticationProvider->authenticate($token);
        }
    }

    /**
     * Authenticate the user with LDAP bind.
     *
     * @param \IMAG\LdapBundle\User\LdapUser  $user
     * @param TokenInterface $token
     *
     * @return boolean
     */
    private function bind(LdapUser $user, TokenInterface $token)
    {
        $this->ldapManager
            ->setUsername($user->getUsername())
            ->setPassword($token->getCredentials());

        return (bool)$this->ldapManager->auth();
    }

    /**
     * Reload user with the username
     *
     * @param \IMAG\LdapBundle\User\LdapUser $user
     * @return \IMAG\LdapBundle\User\LdapUser $user
     */
    private function reloadUser(LdapUser $user)
    {
        try {
            $user = $this->userProvider->refreshUser($user);
        } catch (UsernameNotFoundException $userNotFoundException) {
            if ($this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $userNotFoundException);
            }

            throw $userNotFoundException;
        }

        return $user;
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
        return $token instanceof UsernamePasswordToken
            && $token->getProviderKey() === $this->providerKey;
    }
}
