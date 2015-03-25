<?php

namespace IMAG\LdapBundle\DependencyInjection;

use Symfony\Component\Config\Definition\ConfigurationInterface,
  Symfony\Component\Config\Definition\Builder\TreeBuilder,
  Symfony\Component\Config\Definition\Builder\ArrayNodeDefinition;

class Configuration implements ConfigurationInterface
{
  public function getConfigTreeBuilder()
  {
    $treeBuilder = new TreeBuilder();
    $rootNode = $treeBuilder->root('imag_ldap');
    $rootNode
        ->children()
            ->scalarNode('user_class')
              ->defaultValue("IMAG\LdapBundle\User\LdapUser")
            ->end()
        ->end()
        ;

    $this->addClientNode($rootNode);
    $this->addUserNode($rootNode);
    $this->addGroupsNode($rootNode);
    $this->addRolesNode($rootNode);
    return $treeBuilder;
  }

  private function addClientNode(ArrayNodeDefinition $rootNode)
  {
      $clientNode = $rootNode
          ->children()
              ->arrayNode('client')
                  ->isRequired()
          ;

      $clientNode
          ->children()
              ->scalarNode('host')->isRequired()->cannotBeEmpty()->end()
              ->scalarNode('port')->defaultValue(389)->end()
              ->scalarNode('version')->end()
              ->scalarNode('username')->end()
              ->scalarNode('password')->end()
              ->booleanNode('bind_username_before')->defaultFalse()->end()
              ->scalarNode('referrals_enabled')->end()
              ->scalarNode('network_timeout')->end()
              ->booleanNode('skip_groups')->defaultFalse()->end()
              ->booleanNode('skip_roles')->defaultFalse()->end()
              ->booleanNode('groups_as_roles')->defaultFalse()->end()
          ;
  }

  private function addUserNode(ArrayNodeDefinition $rootNode)
  {
      $userNode = $rootNode
          ->children()
              ->arrayNode('user')
                  ->isRequired()
          ;

      $userNode
          ->children()
              ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
              ->scalarNode('filter')->end()
              ->scalarNode('name_attribute')->defaultValue('uid')->end()
              ->variableNode('attributes')->defaultValue(array())->end()
          ;
  }

  private function addGroupsNode(ArrayNodeDefinition $rootNode)
  {
      $groupsNode = $rootNode
          ->children()
              ->arrayNode('groups')
          ;

      $groupsNode
          ->children()
              ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
              ->scalarNode('filter')->end()
              ->scalarNode('name_attribute')->defaultValue('cn')->end()
              ->scalarNode('user_attribute')->defaultValue('member')->end()
              ->scalarNode('user_id')->defaultValue('dn')
                ->validate()
                  ->ifNotInArray(array('dn', 'username'))
                  ->thenInvalid('Only dn or username')
                ->end()
              ->end()
          ;
  }

  private function addRolesNode(ArrayNodeDefinition $rootNode)
  {
      $rolesNode = $rootNode
          ->children()
              ->arrayNode('roles')
                  ->useAttributeAsKey('role')
                  ->prototype('array')
                      ->performNoDeepMerging()
          ;

      $rolesNode
          ->children()
              ->arrayNode('users')
                  ->beforeNormalization()->ifString()->then(function ($v) { return array($v); })->end()
                  ->prototype('scalar')->end()
              ->end()
              ->arrayNode('groups')
                  ->beforeNormalization()->ifString()->then(function ($v) { return array($v); })->end()
                  ->prototype('scalar')->end()
              ->end()
          ;
  }

}
