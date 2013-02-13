<?php

namespace IMAG\LdapBundle\Provider;

use Symfony\Component\Security\Core\Exception\UnsupportedUserException,
    Symfony\Component\Security\Core\Exception\UsernameNotFoundException,
    Symfony\Component\Security\Core\User\UserInterface,
    Symfony\Component\Security\Core\User\UserProviderInterface;

use IMAG\LdapBundle\Manager\LdapManagerUserInterface,
    IMAG\LdapBundle\User\LdapUser,
    IMAG\LdapBundle\Exception\EmailNotFoundException;

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

        $lm = $this
            ->ldapManager
            ->setEmail(NULL)
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
    
    public function loadUserByEmail($email)
    {
    	if (empty ($email)) {
    	    throw new EmailNotFoundException('The mail is not provided.');
    	}
    	
    	if (!$this->ldapManager->emailExists($email)) {
    	    throw new EmailNotFoundException(sprintf('Mail "%s" not found', $email));
    	}
    	
    	$lm = $this
            ->ldapManager
            ->setUsername(NULL)
            ->setEmail($email)
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
     * Return an LdapUser without any test. Used when the anonym binding is forbidden
     *
     * @param string $username
     * @return IMAG\LdapUser\User\LdapUser $ldapUser
     */
    public function userEqualUsername($username)
    {
        $ldapUser = new LdapUser();
        $ldapUser
            ->setUsername($username)
            ;

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
