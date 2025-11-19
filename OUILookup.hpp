#pragma once
#include <map>
#include <string>

class OUILookup {
  std::map<std::string, std::string> db_;

  static std::string normalize(const std::string &mac_prefix);

public:
  OUILookup() = default;

  bool load(const std::string &filename);

  std::string lookup(const std::string &mac_colon) const;
};
