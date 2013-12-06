<?php

namespace IMAG\LdapBundle\Event;

final class LdapEvents
{
    const PRE_BIND = 'imag_ldap.security.authentication.pre_bind';
    const POST_BIND = 'imag_ldap.security.authentication.post_bind';
}
