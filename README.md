LdapBundle
==========

LdapBundle provides a Ldap authentication system without the `apache mod_ldap`. He use `php-ldap` package with a form to authenticate the users. LdapBundle also can be used for the authorization. He retrieves the  Ldap users' roles.

Contact
-------
You can try to contact me on freenode irc ; channel #symfony-fr ; pseudo : aways

Install
-------
1. Download LdapBundle
2. Configure the Autoloader
3. Enable the Bundle
4. Configure LdapBundle security.yml
6. Import LdapBundle security.yml
7. Import LdapBundle routing
8. Implement Logout

### Download LdapBundle

``` bash
$ git clone git://github.com/BorisMorel/LdapBundle.git src/IMAG/LdapBundle
```

### Configure the Autoloader

``` php
<?php
// app/autoload.php

$loader->registerNamespaces(array(
     // ...
    'IMAG' => __DIR__.'/../src',
));
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
``` yaml
# src/IMAG/LdapBundle/Resources/config/security.yml

security:
  providers:
    ldap:
      id: imag_ldap.security.user.provider
        
  firewalls:
    login:
      pattern: ^/login$
      security: false
     
    restricted_area:
      pattern: ^/
      security: true
      imag_ldap: ~
              
  encoders:
    IMAG\LdapBundle\User\LdapUser: plaintext

  factories:
    - "%kernel.root_dir%/../src/IMAG/LdapBundle/Resources/config/security_factories.xml"

imag_ldap:
  client:
    host: your.host.foo
    port: 389
#    version: 3 # Optional
#    username: foo # Optional
#    password: bar # Optional

  user:
    base_dn: ou=people,dc=host,dc=foo
    filter: (&(foo=bar)(ObjectClass=Person)) #Optional
    name_attribute: uid
  role:
    base_dn: ou=group, dc=host, dc=foo
    filter: (ou=group) #Optional
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

### Import security.yml

``` yaml
# app/config/config.yml

imports:
  - { resource: ../../src/IMAG/LdapBundle/Resources/config/security.yml }
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
You can refer to the official Symfony documentation :
http://symfony.com/doc/2.0/book/security.html#logging-out
