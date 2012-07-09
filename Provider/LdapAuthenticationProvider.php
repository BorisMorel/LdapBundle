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

use IMAG\LdapBundle\Authentication\Token\LdapToken;
use IMAG\LdapBundle\Manager\LdapManagerUserInterface;

class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
    private
        $userProvider,
        $ldapManager,
        $providerKey,
        $hideUserNotFoundExceptions;

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
        $providerKey,
        $hideUserNotFoundExceptions = true
    )
    {
        $this->userProvider = $userProvider;
        $this->ldapManager = $ldapManager;
        $this->providerKey = $providerKey;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (!$this->supports($token)) {
            throw new AuthenticationException('Unsupported token');
        }

        if ($token->getProviderKey() !== $this->providerKey) {
            throw new AuthenticationException('Incorrect provider key');
        }

        try {
            $user = $this->userProvider
                         ->loadUserByUsername($token->getUsername());
        } catch (UsernameNotFoundException $userNotFoundException) {
            if (!$this->hideUserNotFoundExceptions) {
                throw new BadCredentialsException('Bad credentials', 0, $userNotFoundException);
            }

            throw $userNotFoundException;
        }

        if ($this->bind($user, $token)) {
            $ldapToken = new LdapToken($user, '', $user->getRoles());
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
        return (bool)
            $this->ldapManager
            ->setUsername($user->getUsername())
            ->setPassword($token->getCredentials())
            ->auth();
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
        return $token instanceof LdapToken
            || $token instanceof UsernamePasswordToken;
    }

}
