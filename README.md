# LdapBundle

LdapBundle provides a Ldap authentication system without the `apache mod_ldap`. It uses `php-ldap` extension with a form to authenticate the users. LdapBundle also can be used for the authorization. It retrieves the  Ldap users' roles.

## Contact

You can try to contact me on freenode irc ; channel #symfony-fr ; pseudo : aways

## Install

1. Download with composer
3. Enable the Bundle
4. Configure LdapBundle security.yml
7. Import LdapBundle routing
8. Implement Logout
9. Use chain provider
10. Subscribe to PRE_BIND event

### Get the Bundle

### Composer
Modify your composer.json on your project root

``` php
// {root}/composer.json

{
    [...],
    "require": {
        [...],
        "imag/ldap-bundle": "dev-master"
    }
}
```

### Enable the Bundle

``` php
<?php
// app/AppKernel.php

public function registerBundles()
{
    $bundles = array(
    // ...
    new IMAG\LdapBundle\IMAGLdapBundle(),
    );
}
```

### Configure security.yml

**Note:**
> An example of security.yml file is located on Ressource/Docs/

``` yaml
# src/IMAG/LdapBundle/Resources/config/security.yml

security:
  firewalls:
    restricted_area:
      pattern:          ^/
      anonymous:        ~
      provider:         ldap
      imag_ldap:        ~
      # alternative configuration
      # imag_ldap:
      #   login_path:   /ninja/login
      logout:
        path:           /logout
        target:         /

  providers:
    ldap:
      id: imag_ldap.security.user.provider
                
  encoders:
    IMAG\LdapBundle\User\LdapUser: plaintext

  access_control:
    - { path: ^/login,          roles: IS_AUTHENTICATED_ANONYMOUSLY }
    - { path: ^/,               roles: IS_AUTHENTICATED_FULLY }

imag_ldap:
  client:
    host: your.host.foo
    port: 389
#    version: 3 # Optional
#    username: foo # Optional
#    password: bar # Optional
#    network_timeout: 10 # Optional
#    referrals_enabled: true # Optional
#    bind_username_before: true # Optional

  user:
    base_dn: ou=people,dc=host,dc=foo
#    filter: (&(foo=bar)(ObjectClass=Person)) #Optional
    name_attribute: uid
  role:
    base_dn: ou=group, dc=host, dc=foo
#    filter: (ou=group) #Optional
    name_attribute: cn
    user_attribute: member
    user_id: [ dn or username ]
```

**You need to configure the parameters under the imag_ldap section.**

**Note:**

> If are not set, the optional parameters have default values.
> You can disable this ; Just set parameter to NULL.

``` yaml
imag_ldap:
  # ...
  role:
   # ...
   filter: NULL
```

### Import routing

``` yaml
# app/config/routing.yml

imag_ldap:
  resource: "@IMAGLdapBundle/Resources/config/routing.yml"
```

### Implement Logout

Just create a link with logout target.

``` html
<a href="{{ path('logout') }}">logout</a>
```

**Note:**
> You can refer to the official Symfony documentation :
> http://symfony.com/doc/2.0/book/security.html#logging-out

### Chain provider ###

You can chain the login form with other providers. Like, the database_provider, in_memory provider.

``` yml
# security.yml
security:
    firewalls:
        secured_area:
            pattern: ^/
            anonymous: ~
            imag_ldap:
                provider: multiples
            logout:
                path: logout
    providers:
        multiples:
            chain:
                providers: [ldap, db]          
        ldap:
            id: imag_ldap.security.user.provider
        db:
            entity: { class: FQDN\User }
```

**Note: **
> If you have set bind_username_before to true, you must chain the providers with ldap provider in the last position. 

``` yml
# security.yml

providers: [db, ldap]          
```

### Subscribe to PRE_BIND event

Now you can perform you own logic before the user is authenticated on Ldap.
If you want to break the authentication just return an Exception.

To subscribe:
``` xml
<tag name="kernel.event_listener" event="imag_ldap.security.authentication.pre_bind" method="onPreBind" />
```

Exemple:
``` php
<?php
use IMAG\LdapBundle\Event\LdapUserEvent,

public function onPreBind(LdapUserEvent $event)
{
    $user = $event->getUser();
    $config = $this->appContext->getConfig();

    $ldapConf = $config['ldap'];

    if (!in_array($user->getUsername(), $ldapConf['allowed'])) {
        throw new \Exception('Not allowed ldap user');
    }

    $user->addRole('ROLE_LDAP');
}
```
