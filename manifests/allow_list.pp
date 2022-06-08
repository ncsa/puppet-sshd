# @summary Hash of allows to pass to allow_from.pp
#
# @param allows
#   Hash to pass to allow_from.pp, where top level key is the name
#   and the values under that is the hash to pass to allow_from.pp
#
#   See allow_from.pp for allowed values
#
#   Example:
#   ```
#   sshd::allow_list::allows:
#     "dummyuser":
#       hostlist:
#         - "1.1.1.1"
#       users:
#         - "dummyuser"
#       additional_match_params:
#         PubkeyAuthentication: "yes"
#         AuthenticationMethods: "publickey"
#         Banner: "none"
#         MaxAuthTries: "6"
#         MaxSessions: "10"
#         X11Forwarding: "no"
#         AuthorizedKeysFile: "/delta/home/keys/%u"
#     "dummygroup":
#       hostlist:
#         - "2.2.2.2"
#       groups:
#         - "dummygroup"
#       additional_match_params:
#         PubkeyAuthentication: "yes"
#         AuthenticationMethods: "publickey"
#         Banner: "none"
#         MaxAuthTries: "6"
#         MaxSessions: "10"
#         X11Forwarding: "no"
#         AuthorizedKeysFile: "/delta/home/keys/%u"
#   ```
#
# @example
#   include sshd::allow_list
class sshd::allow_list (
  Hash $allows,
) {

  $allows.each | $name, $v | {
    sshd::allow_from { $name: * => $v }
  }
}
