Security.yml
------------

## Ldap configuration
The default values for the filters nodes are removed.
Please set explicitly this values.

``` yaml
user:
  filter: (ou=people)
role:
  filter: (ou=group)

```
### Before:
``` php
<?php
// DependencyInjection/Configuration.php

user:
->scalarNode('filter')->DefaultValue('(ou=people)')->end()

role:
->scalarNode('filter')->DefaultValue('(ou=group)')->end()
```

### Now:
``` php
<?php
// DependencyInjection/Configuration.php

user:
->scalarNode('filter')->end()

role:
->scalarNode('filter')->end()
```

## Firewall
The firewall use access_control directive and only one area.

``` yaml

security:
  firewalls:
    restricted_area:
      pattern:          ^/
[...]

  access_control:
    - { path: ^/login,          roles: IS_AUTHENTICATED_ANONYMOUSLY }
    - { path: ^/,               roles: IS_AUTHENTICATED_FULLY }
```

### Before:

```yaml
# src/IMAG/LdapBundle/Resources/config/security.yml

security:
  firewalls:
    login:
      pattern: ^/login$
      security: false

    restricted_area:
      pattern: ^/
      security: true
      imag_ldap: ~
```

### Now:

```yaml
# src/IMAG/LdapBundle/Resources/config/security.yml

security:
  firewalls:
    restricted_area:
      pattern:          ^/
      anonymous:        ~
      provider:         ldap
      imag_ldap:        ~
      logout:
        path:           /logout
        target:         /

  access_control:
    - { path: ^/login,          roles: IS_AUTHENTICATED_ANONYMOUSLY }
    - { path: ^/,               roles: IS_AUTHENTICATED_FULLY }
```

