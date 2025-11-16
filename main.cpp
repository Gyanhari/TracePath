#include <algorithm>
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <netinet/in.h>
#include <pcap.h>
#include <pcap/pcap.h>
#include <sstream>
#include <string>

std::map<std::string, std::string> oui_db;

void load_oui(const std::string &filename) {
  std::fstream file(filename);
  std::string line;
  while (std::getline(file, line)) {
    if (line.find("hex") == std::string::npos)
      continue;
    std::istringstream iss(line);
    std::string mac_prefix, vendor;
    iss >> mac_prefix;
    std::string temp;
    while (iss >> temp) {
      if (temp.find("hex") != std::string::npos) {
        vendor = "";
        while (iss >> temp) {
          vendor += temp + " ";
        }
      }
    }
    if (!mac_prefix.empty() && !vendor.empty()) {
      oui_db[mac_prefix] = vendor;
    }
  }
  /*
  for (const auto &elem : oui_db) {
    std::cout << elem.first << "\t" << elem.second << std::endl;
  }*/
}

std::string mac_to_string(const u_char *mac) {
  char buf[18];
  snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5]);
  return std::string(buf);
}

std::string colon_to_hyphen(std::string colon_mac) {
  char colon = ':';
  char hyphen = '-';
  std::replace(colon_mac.begin(), colon_mac.end(), colon, hyphen);
  return colon_mac;
}

std::string find_vendor(std::string mac) {
  std::string prefix = mac.substr(0, 8);
  std::string hyphen_prefix = colon_to_hyphen(prefix);
  for (char &c : hyphen_prefix) {
    if (c >= 'a' && c <= 'z') {
      c = c - 32;
    }
  }
  auto it = oui_db.find(hyphen_prefix);
  return it != oui_db.end() ? it->second : "Unknown";
  /* if (it != oui_db.end()) {
     return it->second;
   } else {
     "Unknown";
   }*/
}

void packet_handler(u_char *, const struct pcap_pkthdr *,
                    const u_char *packet) {
  std::string dest_mac = mac_to_string(packet + 0);
  std::string src_mac = mac_to_string(packet + 6);
  std::string src_vendor = find_vendor(src_mac);
  std::string dest_vendor = find_vendor(dest_mac);

  std::cout << " MAC: " << src_vendor << "---->" << dest_vendor << std::endl;

  int ip_version = packet[14] >> 4;
  if (ip_version == 4) {
    struct in_addr src_ip, dest_ip;
    memcpy(&src_ip.s_addr, packet + 26, 4);
    memcpy(&dest_ip.s_addr, packet + 30, 4);
    printf("  IPv4: %s ----> %s \n ", inet_ntoa(src_ip), inet_ntoa(dest_ip));
  } /* else {
    printf("The IP vesion is IPv6.\t It is not implemented now\n");
   }*/
}

int main() {
  std::string filename = "data/oui.txt";
  load_oui(filename);

  pcap_t *handle;
  const char *dev_name = "wlp2s0";
  char err_buffer[PCAP_ERRBUF_SIZE];
  handle = pcap_open_live(dev_name, 65536, 1, 1000, err_buffer);
  if (handle == NULL) {
    fprintf(stderr, "Couldn't open devices %s: %s", dev_name, err_buffer);
    return -1;
  }
  pcap_loop(handle, 5, packet_handler, NULL);
  pcap_close(handle);
  return 0;
}
