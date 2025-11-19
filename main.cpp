#include "PacketSniffer.h"
#include <iostream>

int main() {
  PacketSniffer sniffer;

  sniffer.loadOUI("data/oui.txt");

  if (!sniffer.open("wlp2s0")) {
    return 1;
  }

  std::cout << "\n[*] Starting capture (50 packets, Ctrl+C to stop)\n\n";
  sniffer.start(50);

  return 0;
}
