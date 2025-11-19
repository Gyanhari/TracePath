#include "OUILookup.hpp"
#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <string>

std::string OUILookup::normalize(const std::string &mac_prefix) {
  std::string s = mac_prefix.substr(0, 8);
  s.replace(s.begin(), s.end(), ':', '-');
  std::transform(s.begin(), s.end(), s.begin(), ::toupper);
  return s;
}

bool OUILookup::load(const std::string &filename) {
  std::ifstream file(filename);
  if (!file) {
    std::cerr << "[-] Cannot Open OUI File: " << filename << std::endl;
    return false;
  }
  std::string line;
  while (std::getline(file, line)) {
    if (line.find("(hex)") == std::string::npos)
      continue;

    size_t hex_pos = line.find("(hex)");
    size_t start = line.find_first_not_of('\t');
    if (start == std::string::npos || start >= hex_pos)
      continue;

    std::string raw_prefix = line.substr(start, hex_pos - start);
    raw_prefix = raw_prefix.substr(0, 8);
    std::string key = normalize(raw_prefix);

    size_t vend_start = line.find_first_not_of(" \t", hex_pos + 5);
    std::string vendor =
        vend_start != std::string::npos ? line.substr(vend_start) : "Unkown";
    if (key.size() == 8)
      db_[key] = vendor;
  }
  std::cout << "[+] Loaded " << db_.size() << " OUI entries\n";
  return true;
}
std::string OUILookup::lookup(const std::string &mac) const {
  auto it = db_.find(normalize(mac));
  return it != db_.end() ? it->second : "Unknown";
}
