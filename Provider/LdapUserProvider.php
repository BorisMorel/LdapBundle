<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException,
    Symfony\Component\Security\Core\Exception\UsernameNotFoundException,
    Symfony\Component\Security\Core\User\UserInterface,
    Symfony\Component\Security\Core\User\UserProviderInterface;

use IMAG\LdapBundle\Manager\LdapManagerUserInterface,
    IMAG\LdapBundle\User\LdapUser;

/**
 * LDAP User Provider
 *
 * @author Boris Morel
 * @author Juti Noppornpitak <jnopporn@shiroyuki.com>
 */
class LdapUserProvider implements UserProviderInterface
{
    /**
     * @var \IMAG\LdapBundle\Manager\LdapManagerUserInterface
     */
    private $ldapManager;

    /**
     * Constructor
     *
     * @param \IMAG\LdapBundle\Manager\LdapManagerUserInterface $ldapManager
     */
    public function __construct(LdapManagerUserInterface $ldapManager)
    {
        $this->ldapManager = $ldapManager;
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        // Throw the exception if the username is not provided.
        if (empty($username)) {
            throw new UsernameNotFoundException('The username is not provided.');
        }

        // Throw the exception if the username is not found.
        if(!$this->ldapManager->exists($username)) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found', $username));
        }

        $lm = $this->ldapManager
            ->setUsername($username)
            ->doPass();

        $ldapUser = new LdapUser();
        $ldapUser
            ->setUsername($lm->getUsername())
            ->setEmail($lm->getEmail())
            ->setRoles($lm->getRoles())
            ->setDn($lm->getDn())
            ->setAttributes($lm->getAttributes());

        return $ldapUser;
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof LdapUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return $class === 'IMAG\LdapBundle\User\LdapUser';
    }
}
