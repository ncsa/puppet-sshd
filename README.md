# sshd

![pdk-validate](https://github.com/ncsa/puppet-sshd/workflows/pdk-validate/badge.svg)
![yamllint](https://github.com/ncsa/puppet-sshd/workflows/yamllint/badge.svg)

Manage base sshd_config settings and allow_ssh access for users and groups from
specified sources.

## Dependencies
- [herculesteam/augeasfacter](https://github.com/herculesteam/augeasfacter)
- [herculesteam/augeasproviders](https://forge.puppet.com/herculesteam/augeasproviders)
- [MiamiOH/pam_access](https://forge.puppet.com/MiamiOH/pam_access)
- [ncsa/puppet-sssd](https://github.com/ncsa/puppet-sssd)
- [puppetlabs/firewall](https://forge.puppet.com/puppetlabs/firewall)

## Reference

[REFERENCE.md](REFERENCE.md)

### define sshd::allow_from (
-    Array[ String, 1 ]   $hostlist,
-    Array[ String ]      $users                   = [],
-    Array[ String ]      $groups                  = [],
-    Hash[ String, Data ] $additional_match_params = {},
### class sshd (
-  Hash              $allow_list,
-  Boolean           $banner_ignore,
-  Hash              $config,
-  String            $config_file,
-  Hash[String,Hash] $config_matches,
-  Hash              $config_subsystems,
-  Boolean           $manage_service,
-  Array[String]     $required_packages,   #per OS
-  Array[String]     $revoked_keys,
-  String            $revoked_keys_file,   #per OS
-  String            $service_name,
-  Array             $trusted_subnets,
-  Optional[String]  $banner = undef,
