#include "net_permission.h"
#include "debug_utils-inl.h"
#include "json_utils.h"
#include "util.h"

#include <string>
#include <string_view>
#include <vector>
#include <regex>
#include <cctype>

namespace node {

namespace permission {

void NetPermission::Apply(Environment* env,
                          const std::vector<std::string>& allow,
                          PermissionScope scope) {
  // For Debug
  auto cleanup = OnScopeLeave([&]() { Print(); });
  using std::string_view_literals::operator""sv;
  for (const std::string& res : allow) {
    const std::vector<std::string_view> addresses = SplitString(res, ","sv);
    for (const auto& address : addresses) {
      // address is like *, */*, host, host/*, host/port, */port
      if (address != "*"sv && address != "*/*"sv) {
        GrantAccess(scope, address);
        continue;
      }
      deny_all_udp_ = false;
      allow_all_udp_ = true;
      granted_udp_.clear();
    }
  }
}

void NetPermission::GrantAccess(PermissionScope scope,
                                const std::string_view& param) {
  if (param.empty()) {
    return;
  }
  ParseResult result = Parse(param);
  std::bitset<128> netmask;
  std::bitset<128> network;
  if (!result.netmask.empty()) {
    std::regex rx("^[0-9]+$");
    if (std::regex_match(result.netmask.begin(),result.netmask.end(), rx)) {
      int len = std::stoi(result.netmask);
      int position = result.is_ipv6 ? 128 : 32;
      while(len--) {
        netmask.set(--position, true);
      }
    } else {
      if (result.is_ipv6) {
        char netmask_buf[sizeof(struct in6_addr)];
        if (uv_inet_pton(AF_INET6, result.netmask.c_str(), &netmask_buf) == 0) {
          netmask = std::bitset<128>(netmask_buf);
        } else {
          UNREACHABLE();
        }
      } else {
        char netmask_buf[sizeof(struct in_addr)];
        if (uv_inet_pton(AF_INET, result.netmask.c_str(), &netmask_buf) == 0) {
          netmask = std::bitset<128>(netmask_buf);
        } else {
          UNREACHABLE();
        }
      }
    }
    std::bitset<128> ip;
    if (result.is_ipv6) {
      char ip_buf[sizeof(struct in6_addr)];
      if (uv_inet_pton(AF_INET6, result.host_or_ip.c_str(), &ip_buf) == 0) {
        int count = 128;
        int len = sizeof(struct in6_addr);
        for (int i = 0; i < len; i++) {
          std::bitset<8> binary(ip_buf[i]);
          for (int j = 0;j < 8 ;j++) {
            ip.set(--count, binary.test(j));
          }
        }
      } else {
        UNREACHABLE();
      }
    } else {
      char ip_buf[sizeof(struct in_addr)];
      if (uv_inet_pton(AF_INET, result.host_or_ip.c_str(), &ip_buf) == 0) {
        ip = std::bitset<128>(ip_buf);
      } else {
        UNREACHABLE();
      }
    }
    network = netmask & ip;
  }
  auto iter = granted_udp_.find(result.host_or_ip);
  NetNode *node = new NetNode(result.port, netmask, network);
  if (iter == granted_udp_.end()) {
    granted_udp_.insert(
        std::pair<std::string, std::vector<NetNode*>>(result.host_or_ip, {node}));
  } else {
    // we do not need to handle other ports if port(iter->second[0]) is equal
    // to *
    if (iter->second[0]->port != "*") {
      // clear all the old ports if the new port is equal to *
      if (result.port == "*") {
        iter->second.clear();
        iter->second.push_back(node);
      } else  { // std::find_if(iter->second.begin(), iter->second.end(), result.port) == iter->second.end()
        // insert the port if it does not exsit
        iter->second.push_back(node);
      }
    }
  }
  deny_all_udp_ = false;
}

void NetPermission::Print() const {
  if (UNLIKELY(per_process::enabled_debug_list.enabled(
          DebugCategory::PERMISSION_MODEL))) {
    auto fn = [&](const address_map* rules) {
      JSONWriter writer(std::cout, false);
      writer.json_start();
      for (const auto& iter : *rules) {
        writer.json_keyvalue("host_or_ip", iter.first);
        writer.json_arraystart("Nodes");
        for (const auto& item : iter.second) {
          writer.json_start();
          writer.json_keyvalue("port", item->port);
          writer.json_keyvalue("netmask", item->netmask.to_string());
          writer.json_keyvalue("network", item->network.to_string());
          writer.json_end();
        }
        writer.json_arrayend();
      }

      writer.json_end();
      std::cout << std::endl << std::endl;
    };
    std::cout << "net-udp-net: " << std::endl;
    std::cout << "  deny_all_udp_: " << deny_all_udp_ << std::endl;
    std::cout << "  allow_all_udp_: " << allow_all_udp_ << std::endl;
    fn(&granted_udp_);
  }
}

bool NetPermission::is_granted(Environment* env,
                               PermissionScope perm,
                               const std::string_view& param = "") const {
  switch (perm) {
    case PermissionScope::kNetUDP:
      return !deny_all_udp_ &&
             (allow_all_udp_ ||
              check_permission(&granted_udp_, param));
    default:
      return false;
  }
}

bool NetPermission::check_permission(const address_map* rules,
                                     const std::string_view& param) const {
  if (param.empty()) {
    return false;
  }
  ParseResult result = Parse(param);
  auto fn = [&](auto iter) {
    if (iter->second[0]->port == "*") {
      return true;
    }
    for (int i = 0; i<iter->second.size(); ++i) {
      if (iter->second[i]->netmask.any()) {
        std::bitset<128> ip;
        char ip_buf[sizeof(struct in6_addr)];
        int res = uv_inet_pton(AF_INET6, result.host_or_ip.c_str(), &ip_buf);
        if (res == 0) {
          int count = 128;
          for (int i = 0; i < sizeof(struct in6_addr); i++) {
            std::bitset<8> binary(ip_buf[i]);
            for (int j = 0;j < 8 ;j++) {
              ip.set(--count, binary.test(j));
            }
          }
        } else {
          UNREACHABLE();
        }
        std::bitset<128> network =  iter->second[i]->netmask & ip;
        if (network.to_string() == iter->second[i]->network.to_string()) {
          return true;
        }
      }
      if (iter->second[i]->port == result.port) {
        return true;
      }
    }

    // if (std::find(iter->second.begin(), iter->second.end(), result.port) !=
    //     iter->second.end()) {
    //   return true;
    // }
    return false;
  };
  // for (std::unordered_map<std::string, std::vector<NetNode*>>::iterator it = rules->begin(); it != rules->end(); it++) {
  //   //auto iter = rules->find("result.host_or_ip");
  //   if (fn(rules->begin())) {
  //     return true;
  //   }
  // }
   if (fn(rules->begin())) {
      return true;
    }
  
  // if (result.host_or_ip != "*") {
  //   iter = rules->find("*");
  //   if (iter != rules->end() && fn(iter)) {
  //     return true;
  //   }
  // }
  return false;
}

NetPermission::ParseResult NetPermission::Parse(const std::string_view& param) const {
  using std::string_view_literals::operator""sv;
  size_t ipv6_idx = param.find("]"sv);
  bool is_ipv6 = ipv6_idx != std::string::npos;
  size_t net_mask_idx = param.find("/"sv);
  bool has_net_mask = net_mask_idx != std::string::npos;
  size_t port_idx = param.find(":"sv, is_ipv6 ? ipv6_idx : 0);
  bool has_port = port_idx != std::string::npos;
  std::string host_or_ip;
  std::string net_mask;
  std::string port;
  if (is_ipv6) {
    host_or_ip = param.substr(1, ipv6_idx - 1);
  } else {
    if (has_net_mask) {
      host_or_ip = param.substr(0, net_mask_idx);
    } else if (has_port) {
      host_or_ip = param.substr(0, port_idx);
    } else {
      host_or_ip = param;
    }
  }
  if (has_net_mask) {
    if (has_port) {
      net_mask = param.substr(net_mask_idx + 1, port_idx - net_mask_idx - 1);
    } else {
      net_mask = param.substr(net_mask_idx + 1);
    }
  }
  if (has_port) {
    port = param.substr(port_idx + 1);
  }
  // --allow-net-udp=host
  if (port.empty()) {
    port = "*";
  }
  return ParseResult(host_or_ip, net_mask, port, is_ipv6);
}

}  // namespace permission
}  // namespace node
