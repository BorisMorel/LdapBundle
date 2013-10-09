<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException,
    Symfony\Component\Security\Core\Exception\UsernameNotFoundException,
    Symfony\Component\Security\Core\User\UserInterface,
    Symfony\Component\Security\Core\User\UserProviderInterface;

use IMAG\LdapBundle\Manager\LdapManagerUserInterface,
    IMAG\LdapBundle\User\LdapUserInterface;

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
     * @var string
     */
    private $bindUsernameBefore;

    /**
     * The class name of the User model
     * @var string
     */
    private $userClass;

    /**
     * Constructor
     *
     * @param \IMAG\LdapBundle\Manager\LdapManagerUserInterface $ldapManager
     * @param bool|string                                       $bindUsernameBefore
     * @param string                                            $userClass
     */
    public function __construct(LdapManagerUserInterface $ldapManager, $bindUsernameBefore = false, $userClass)
    {
        $this->ldapManager = $ldapManager;
        $this->bindUsernameBefore = $bindUsernameBefore;
        $this->userClass = $userClass;
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

        if (true === $this->bindUsernameBefore) {
            $ldapUser = $this->simpleUser($username);
        } else {
            $ldapUser = $this->anonymousSearch($username);
        }

        return $ldapUser;
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof LdapUserInterface) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }

        return $this->loadUserByUsername($user->getUsername());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return is_subclass_of($class, '\IMAG\LdapBundle\User\LdapUserInterface');
    }

    private function simpleUser($username)
    {
        $ldapUser = new $this->userClass;
        $ldapUser->setUsername($username);

        return $ldapUser;
    }

    private function anonymousSearch($username)
    {
        // Throw the exception if the username is not found.
        if(!$this->ldapManager->exists($username)) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found', $username));
        }

        $lm = $this->ldapManager
            ->setUsername($username)
            ->doPass();

        $ldapUser = new $this->userClass;

        $ldapUser
            ->setUsername($lm->getUsername())
            ->setEmail($lm->getEmail())
            ->setRoles($lm->getRoles())
            ->setDn($lm->getDn())
            ->setCn($lm->getCn())
            ->setAttributes($lm->getAttributes())
            ->setGivenName($lm->getGivenName())
            ->setSurname($lm->getSurname())
            ->setDisplayName($lm->getDisplayName())
            ;

        return $ldapUser;
    }
}
