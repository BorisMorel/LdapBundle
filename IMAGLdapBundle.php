<?php

/*
 * This file is part of the Symfony framework.
 *
 * (c) Fabien Potencier <fabien@symfony.com>
 *
 * This source file is subject to the MIT license that is bundled
 * with this source code in the file LICENSE.
 */

namespace IMAG\LdapBundle;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

use IMAG\LdapBundle\Factory\LdapFactory;

/**
 * LDAP Bundle
 *
 * @author Boris Morel
 * @author Juti Noppornpitak <jnopporn@shiroyuki.com>
 */
class IMAGLdapBundle extends Bundle
{
    public function boot()
    {
        if (!function_exists('ldap_connect')) {
            throw new \Exception("module php-ldap isn't installed");
        }
    }

    /**
     * Build the bundle.
     *
     * This is used to register the security listener to support Symfony 2.1.
     *
     * @param \Symfony\Component\DependencyInjection\ContainerBuilder $container
     */
    public function build(ContainerBuilder $container)
    {
        parent::build($container);

        $extension = $container->getExtension('security');
        $extension->addSecurityListenerFactory(new LdapFactory);
    }
}
