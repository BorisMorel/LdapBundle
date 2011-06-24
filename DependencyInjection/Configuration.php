<?php

namespace IMAG\LdapBundle\DependencyInjection;

use Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition,
  Symfony\Component\Config\Definition\Builder\TreeBuilder;

class Configuration
{
  public function getConfigTree()
  {
    $treeBuilder = new TreeBuilder();
    $rootNode = $treeBuilder->root('imag_ldap');
    $rootNode
      ->children()
      ->arrayNode('provider')
        ->children()
        ->arrayNode('ldap')
          ->children()
            ->scalarNode('host')->end()
            ->scalarNode('port')->end()
            ->scalarNode('user_base_dn')->end()
            ->scalarNode('user_filter')->end()
            ->scalarNode('user_attribute')->end()
          ->end()
        ->end()
      ->end();

    return $treeBuilder->buildTree();      
  }
}
