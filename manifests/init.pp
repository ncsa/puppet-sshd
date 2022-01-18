# @summary Configure default sshd settings
#
# Configure default sshd settings
#
# @param trusted_subnets
#   Array of IPs and CIDRs to be allowed through the firewall
#   Values from multiple sources are merged
#
# @param config
#   Hash of global config settings
#   Defaults provided by this module
#   Values from multiple sources are merged
#   Key collisions are resolved in favor of the higher priority value
#
# @param config_matches
#   Hash of config "match" conditions and settings.
#   Keys are match condition.
#   Vals are a hash of sshd_config settings for the match condition.
#   Expected format:
#   ```
#   ---
#   sshd::config_matches:
#     Unique condition one:
#       SettingOne: val
#       SettingTwo:
#         - val2
#         - val3
#     Unique condition two:
#       SettingOne: val
#       SettingTwo:
#         - val2
#         - val3
#   Note that condition strings must be valid sshd_config criteria-pattern pairs
#   Values from multiple sources are merged
#   Key collisions are resolved in favor of the higher priority value
#   Merges are deep to allow use of the knockout_prefix '-' (to remove a key
#   from the final result).
#   ```
# @param banner
#   A string to create a banner to display before login.
#   Use to display before authentication.
#   Defining this automatically sets the sshd_config option.
#   If you define the Banner config in hiera, the Puppet agent will not run.
#   Example of hiera data:
#   ```
#   sshd::banner: |2+
#
#   Login with NCSA Kerberos + Duo multi-factor.
#
#   DUO Documentation:  https://go.ncsa.illinois.edu/2fa
#   ```
# @param revoked_keys
#   List of ssh public keys to disallow.
#   Values from multiple sources are merged.
#
# @param required_packages
#   List of package names to be installed (OS specific).
#   (Defaults provided by module should be sufficient).
#
# @example
#   include sshd
class sshd (
  Hash              $config,
  Hash[String,Hash] $config_matches,
  Array[String]     $required_packages,   #per OS
  Array[String]     $revoked_keys,
  String            $revoked_keys_file,   #per OS
  Array             $trusted_subnets,
  Optional[String]  $banner = undef,
) {

  # PACKAGES
  ensure_packages( $required_packages, {'ensure' => 'present'} )

  # SERVICE
  service { 'sshd' :
    ensure     => running,
    enable     => true,
    hasstatus  => true,
    hasrestart => true,
    require    => Package[ $required_packages ],
  }

  # FIREWALL
  each($trusted_subnets) | $index, $sshd_subnet | {
    firewall { "022 allow SSH from ${sshd_subnet}":
      dport  => 22,
      proto  => tcp,
      source => $sshd_subnet,
      action => accept,
    }
  }

  # REVOKED KEYS
  file { $revoked_keys_file :
    ensure  => present,
    owner   => root,
    group   => root,
    mode    => '0644',
    content => join( $revoked_keys, "\n" ),
    notify  => Service['sshd'],
  }
  sshd_config {
    'RevokedKeys' :
      value => $revoked_keys_file,
    ;
  }

  # SSHD CONFIG SETTINGS

  # Default sshd_config attributes
  $config_defaults = {
    'notify' => Service[ sshd ],
  }
  $config_match_defaults = $config_defaults + { 'position' => 'before first match' }

  $puppet_file_header = '# This file is managed by Puppet - Changes may be overwritten'
  $sshd_config_file = '/etc/ssh/sshd_config'
  exec { 'add puppet header to sshd_config':
    command => "sed -i '1s/^/${puppet_file_header}\\n/' '${sshd_config_file}'",
    unless  => "grep '${puppet_file_header}' ${sshd_config_file}",
    path    => [ '/bin', '/usr/bin' ],
  }

  # Apply global sshd_config settings
  $config.each | $key, $val | {
    sshd_config {
      $key :
        value => $val,
      ;
      default:
        * => $config_defaults,
      ;
    }
  }

  # Process config match settings from Hiera
  $config_matches.each | $condition, $data | {
    # Create config match section
    sshd_config_match {
      $condition :
      ;
      default:
        * => $config_match_defaults,
      ;
    }
    # Set each setting inside the match section
    $data.each | $key, $val | {
      sshd_config {
        "${condition} ${key}" :
          key       => $key,
          value     => $val,
          condition => $condition,
        ;
        default:
          * => $config_defaults,
        ;
      }
    }
  }

  #SSH Banner creation
  if ($banner != undef) {
    file { '/etc/sshbanner':
      ensure  => file,
      content => $banner,
      mode    => '0644',
      owner   => '0',
      group   => '0',
    }
    sshd_config {
      'Banner' :
        value => '/etc/sshbanner',
      ;
    }
  }
}
