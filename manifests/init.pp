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
#
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
    Array             $trusted_subnets,
    Hash              $config,
    Hash[String,Hash] $config_matches,
    Array[String]     $revoked_keys,

    # Module defaults should be sufficient
    Array[String] $required_packages,   #per OS
    String        $revoked_keys_file,   #per OS
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

    # SSHD CONFIG SETTINGS

    # Default sshd_config attributes
    $config_defaults = {
        'notify' => Service[ sshd ],
    }
    $config_match_defaults = $config_defaults + { 'position' => 'before first match' }

    # Apply global sshd_config settings
    $config.each | $key, $val | {
        sshd_config {
            $key : value => $val,
            ;
            default: * => $config_defaults,
            ;
        }
    }

    # Process config match settings from Hiera
    $config_matches.each | $condition, $data | {
        # Create config match section
        sshd_config_match {
            $condition :
            ;
            default: * => $config_match_defaults,
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
                default: * => $config_defaults,
                ;
            }
        }
    }

}
