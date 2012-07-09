<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface,
    Symfony\Component\Security\Core\User\UserProviderInterface,
    Symfony\Component\Security\Core\Authentication\Token\TokenInterface,
    Symfony\Component\Security\Core\User\UserInterface,
    Symfony\Component\Security\Core\Exception\AuthenticationException,
    IMAG\LdapBundle\Manager\LdapManagerUserInterface,
    IMAG\LdapBundle\Authentication\Token\LdapToken,
    Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;

class LdapAuthenticationProvider implements AuthenticationProviderInterface
{
    private
        $userProvider,
        $ldapManager,
        $providerKey;
 
    /**
     * Constructor
     *
     * @param UserProviderInterface    $userProvider
     * @param LdapManagerUserInterface $ldapManager
     * @param string                   $providerKey
     */
    public function __construct(UserProviderInterface $userProvider, LdapManagerUserInterface $ldapManager, $providerKey)
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

        $user = $this->userProvider
                     ->loadUserByUsername($token->getUsername());
     
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
