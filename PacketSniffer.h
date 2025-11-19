#pragma once
#include "OUILookup.h"
#include <cstddef>
#include <pcap.h>
#include <string>

class PacketSniffer {
  pcap_t *handle = nullptr;
  OUILookup oui_;
  static void packetHandler(u_char *user, const struct pcap_pkthdr *header,
                            const u_char *packet);
  void processPacket(const struct pcap_pkthdr *header,
                     const u_char *packet) const;

  static std::string macToString(const u_char *mac);
  static std::string ipToString(const void *ip, int family);

public:
  PacketSniffer() = default;
  ~PacketSniffer();
  bool open(const std::string &device = " ");
  void loadOUI(const std::string &path) { oui_.load(path); }
  void start(int packet_count = 50);
};
