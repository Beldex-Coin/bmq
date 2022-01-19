#pragma once
#include <iosfwd>
#include <string>
#include <cstring>
#include <unordered_set>

namespace bmq {

/// Authentication levels for command categories and connections
enum class AuthLevel {
    denied, ///< Not actually an auth level, but can be returned by the AllowFunc to deny an incoming connection.
    none, ///< No authentication at all; any random incoming ZMQ connection can invoke this command.
    basic, ///< Basic authentication commands require a login, or a node that is specifically configured to be a public node (e.g. for public RPC).
    admin, ///< Advanced authentication commands require an admin user, either via explicit login or by implicit login from localhost.  This typically protects administrative commands like shutting down, starting mining, or access sensitive data.
};

std::ostream& operator<<(std::ostream& os, AuthLevel a);

/// The access level for a command category
struct Access {
    /// Minimum access level required
    AuthLevel auth;
    /// If true only remote MNs may call the category commands
    bool remote_mn;
    /// If true the category requires that the local node is a MN
    bool local_mn;

    /// Constructor.  Intentionally allows implicit conversion from an AuthLevel so that an
    /// AuthLevel can be passed anywhere an Access is required (the resulting Access will have both
    /// remote and local mn set to false).
    Access(AuthLevel auth = AuthLevel::none, bool remote_mn = false, bool local_mn = false)
        : auth{auth}, remote_mn{remote_mn}, local_mn{local_mn} {}
};

/// Simple hash implementation for a string that is *already* a hash-like value (such as a pubkey).
/// Falls back to std::hash<std::string> if given a string smaller than a size_t.
struct already_hashed {
    size_t operator()(const std::string& s) const {
        if (s.size() < sizeof(size_t))
            return std::hash<std::string>{}(s);
        size_t hash;
        std::memcpy(&hash, &s[0], sizeof(hash));
        return hash;
    }
};

/// std::unordered_set specialization for specifying pubkeys (used, in particular, by
/// BMQ::set_active_mns and BMQ::update_active_mns); this is a std::string unordered_set that
/// also uses a specialized trivial hash function that uses part of the value itself (i.e. the
/// pubkey) directly as a hash value.  (This is nice and fast for uniformly distributed values like
/// pubkeys and a terrible hash choice for anything else).
using pubkey_set = std::unordered_set<std::string, already_hashed>;


}
