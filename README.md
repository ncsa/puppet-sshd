# sshd

![pdk-validate](https://github.com/ncsa/puppet-sshd/workflows/pdk-validate/badge.svg)
![yamllint](https://github.com/ncsa/puppet-sshd/workflows/yamllint/badge.svg)

Manage base sshd_config settings and allow_ssh access for users and groups from
specified sources.

## Dependencies
- [MiamiOH/pam_access](https://forge.puppet.com/MiamiOH/pam_access)
- [herculesteam/augeasproviders](https://forge.puppet.com/herculesteam/augeasproviders)
- [ncsa/puppet-sssd](https://github.com/ncsa/puppet-sssd)
- [puppetlabs/firewall](https://forge.puppet.com/puppetlabs/firewall)
- [woodsbw/augeasfacter](https://github.com/woodsbw/augeasfacter)

## Reference

[REFERENCE.md](REFERENCE.md)

### define sshd::allow_from (
-    Array[ String, 1 ]   $hostlist,
-    Array[ String ]      $users                   = [],
-    Array[ String ]      $groups                  = [],
-    Hash[ String, Data ] $additional_match_params = {},
### class sshd (
-    Boolean           $banner_ignore,
-    Hash              $config,
-    Hash[String,Hash] $config_matches,
-    Array[String]     $required_packages,
-    Array[String]     $revoked_keys,
-    String            $revoked_keys_file,
-    Array             $trusted_subnets,
-    Optional[String]  $banner = undef,
