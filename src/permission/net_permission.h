#ifndef SRC_PERMISSION_NET_PERMISSION_H_
#define SRC_PERMISSION_NET_PERMISSION_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include <unordered_map>
#include <bitset>
#include "uv.h"
#include "permission/permission_base.h"

namespace node {

namespace permission {

class NetPermission final : public PermissionBase {
 public:
  void Apply(Environment* env,
             const std::vector<std::string>& allow,
             PermissionScope scope) override;
  bool is_granted(Environment* env,
                  PermissionScope perm,
                  const std::string_view& param) const override;
  

  struct NetNode {
    std::string port;
    std::bitset<128> netmask;
    std::bitset<128> network;
    explicit NetNode(const std::string& port_,
                     std::bitset<128>& netmask_,
                     std::bitset<128>& network_)
          : port(port_), netmask(netmask_), network(network_) {}
  };
  struct ParseResult {
    std::string host_or_ip;
    std::string netmask;
    std::string port;
    bool is_ipv6;
    explicit ParseResult(const std::string host_or_ip_,
                         const std::string& netmask_,
                         const std::string& port_,
                         const bool is_ipv6_)
          : host_or_ip(host_or_ip_),
            netmask(netmask_),
            port(port_),
            is_ipv6(is_ipv6_) {}
  };

  using address_map = std::unordered_map<std::string, std::vector<NetNode*>>;
  using address_netmask_map = std::vector<std::string, NetNode*>;
 private:
  bool check_permission(const address_map* rules,
                        const std::string_view& param) const;
  void GrantAccess(PermissionScope scope, const std::string_view& param);
  void Print() const;
  ParseResult Parse(const std::string_view& param) const ;
  address_map granted_udp_;

  bool deny_all_udp_ = true;

  bool allow_all_udp_ = false;
};

}  // namespace permission

}  // namespace node

#endif  // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif  // SRC_PERMISSION_NET_PERMISSION_H_
