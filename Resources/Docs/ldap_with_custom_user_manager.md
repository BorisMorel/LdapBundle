Using a custom user manager with LDAP authentication
========================

One does not need to rely on having a full-fledged user entity in the LDAP
directory. It is not so uncommon to use the directories as authentication-only
services (e.g. because of organizational restrictions), but needed user
attributes have to be stored somewhere else. The following example
uses the user manager provided by the [FOSUserBundle](https://github.com/FriendsOfSymfony/FOSUserBundle), but basically any
solution can be used. A configured and working FOSUserBundle instance is assumed
for the rest of this documentation.

### Create a User entity

First a user entity implementing the necessary interfaces needs to be created
and customized:

```php
<?php
// src/Acme/DemoBundle/Entity/User.php

namespace Acme\DemoBundle\Entity;

use FOS\UserBundle\Entity\User as BaseUser;
use Doctrine\ORM\Mapping as ORM;
use IMAG\LdapBundle\User\LdapUserInterface;

use Symfony\Component\Security\Core\User\UserInterface;

/**
 * @ORM\Entity
 * @ORM\Table(name="fos_user")
 */
class User extends BaseUser implements LdapUserInterface
{
    /**
     * @ORM\Id
     * @ORM\Column(type="integer")
     * @ORM\GeneratedValue(strategy="AUTO")
     */
    protected $id;

    /**
     * @ORM\Column(name="dn", type="string", length=255)
     */
    protected $dn;


    protected $attributes;

    public function __construct()
    {
        parent::__construct();
        // your own logic
    }

    public function getDn()
    {
        return $this->dn;
    }

    public function setDn($dn)
    {
        $this->dn = $dn;

        return $this;
    }

    public function getAttributes()
    {
        return $this->attributes;
    }

    public function setAttributes(array $attributes)
    {
        $this->attributes = $attributes;

        return $this;
    }

    public function getAttribute($name)
    {
        return isset($this->attributes[$name]) ? $this->attributes[$name] : null;
    }

    public function isEqualTo(UserInterface $user)
    {
        if (!$user instanceof LdapUserInterface
            || $user->getUsername() !== $this->username
            || $user->getEmail() !== $this->email
            || count(array_diff($user->getRoles(), $this->getRoles())) > 0
            || $user->getDn() !== $this->dn
        ) {
            return false;
        }

        return true;
    }

    public function serialize()
    {
        return serialize(array(
            $this->password,
            $this->salt,
            $this->usernameCanonical,
            $this->username,
            $this->emailCanonical,
            $this->email,
            $this->expired,
            $this->locked,
            $this->credentialsExpired,
            $this->enabled,
            $this->id,
            $this->roles,
            $this->dn,
        ));
    }

    public function unserialize($serialized)
    {
        list(
            $this->password,
            $this->salt,
            $this->usernameCanonical,
            $this->username,
            $this->emailCanonical,
            $this->email,
            $this->expired,
            $this->locked,
            $this->credentialsExpired,
            $this->enabled,
            $this->id,
            $this->roles,
            $this->dn,
        ) = unserialize($serialized);
    }

}
```
As this user model extends the FOSUserBundle base user model, the serialization
and equality functions are overriden to accomodate the need of the distinguished
name (`$dn`).

### Update configuration

The generated and configured user entity needs to be registered in the configuration (`config.yml`):
```yml
imag_ldap:
  client:
    host: your.host.foo
    port: 389

  user:
    base_dn: ou=people, dc=host, dc=foo
    name_attribute: uid

  user_class: Acme\DemoBundle\Entity\User
```

The encoder in `security.yml` needs to be set as well:
```yml
security:
    encoders:
        Acme\DemoBundle\Entity\User: plaintext
```

### Create custom user provider service

Now all that's left is the creation of a custom `LdapUserProvider` service that
handles the creation and population of the user entity during requests:
```php
<?php

namespace Acme\DemoBundle\Security\User\Provider;

use Symfony\Component\Security\Core\Exception\UsernameNotFoundException,
    Symfony\Component\Security\Core\Exception\UnsupportedUserException,
    Symfony\Component\Security\Core\User\UserProviderInterface,
    Symfony\Component\Security\Core\User\UserInterface,
    Symfony\Component\DependencyInjection\ContainerInterface;

use IMAG\LdapBundle\Manager\LdapManagerUserInterface,
    IMAG\LdapBundle\User\LdapUserInterface;
use FOS\UserBundle\Model\UserManagerInterface;

class LdapUserProvider implements UserProviderInterface
{
    /**
     * @var \IMAG\LdapBundle\Manager\LdapManagerUserInterface
     */
    private $ldapManager;

    /**
     * @var \FOS\UserBundle\Model\UserManagerInterface
     */
    protected $userManager;

    /**
     * @var \Symfony\Component\Validator\Validator
     */
    protected $validator;

    /**
     * Constructor
     *
     * @param LdapManagerUserInterface $ldapManager
     * @param UserManagerInterface     $userManager
     * @param Validator                $validator
     */
    public function __construct(LdapManagerUserInterface $ldapManager, UserManagerInterface $userManager, $validator)
    {
        $this->ldapManager = $ldapManager;
        $this->userManager = $userManager;
        $this->validator = $validator;
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

        // check if the user is already know to us
        $user = $this->userManager->findUserBy(array("username" => $username));

        // Throw an exception if the username is not found.
        if(empty($user) && !$this->ldapManager->exists($username)) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found', $username));
        }

        $lm = $this->ldapManager
            ->setUsername($username)
            ->doPass();

        if (empty($user)) {
            $user = $this->userManager->createUser();
            $user->setRoles($lm->getRoles());
            $user
                ->setUsername($lm->getUsername())
                ->setPassword("")
                ->setDn($lm->getDn())
                ->setEmail($lm->getEmail());

            $this->userManager->updateUser($user);
        }

        return $user;
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
        return $this->userManager->supportsClass($class);
    }
}
```

### Register the service

Symfony needs to be told to use the created service by overriding the default
provider in `services.xml`. Other services needed (like the `FOSUserManager`)
or the user class to be used are passed to the constructor:
```xml
<service id="imag_ldap.security.user.provider" class="Acme\DemoBundle\Security\User\Provider\LdapUserProvider">
  <argument type="service" id="imag_ldap.ldap_manager" />
  <argument type="service" id="fos_user.user_manager" />
  <argument type="service" id="validator" />
  <argument>%imag_ldap.model.user_class%</argument>
</service>
```

After flushing the cache a user is populated from the database via the user
manager provided by the `FOSUserBundle` and authenticated by the directory. :smirk: