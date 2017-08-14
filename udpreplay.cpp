/*
Copyright (c) 2017 Erik Rigtorp <erik@rigtorp.se>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
 */

#include <cstring>
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  static const char usage[] =
      " [-i iface] [-l] [-s speed] [-t ttl] pcap\n"
      "\n"
      "  -i iface    interface to send packets through\n"
      "  -l          enable loopback\n"
      "  -s speed    replay speed relative to pcap timestamps\n"
      "  -t ttl      packet ttl";

  int ifindex = 0;
  int loopback = 0;
  double speed = 1;
  int ttl = -1;

  int opt;
  while ((opt = getopt(argc, argv, "i:ls:t:")) != -1) {
    switch (opt) {
    case 'i':
      ifindex = if_nametoindex(optarg);
      if (ifindex == 0) {
        std::cerr << "if_nametoindex: " << strerror(errno) << std::endl;
        return 1;
      }
      break;
    case 'l':
      loopback = 1;
      break;
    case 's':
      speed = std::stod(optarg);
      break;
    case 't':
      ttl = std::stoi(optarg);
      break;
    default:
      std::cerr << "usage: " << argv[0] << usage << std::endl;
      return 1;
    }
  }
  if (optind >= argc) {
    std::cerr << "usage: " << argv[0] << usage << std::endl;
    return 1;
  }

  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd == -1) {
    std::cerr << "socket: " << strerror(errno) << std::endl;
    return 1;
  }

  if (ifindex != 0) {
    ip_mreqn mreqn;
    memset(&mreqn, 0, sizeof(mreqn));
    mreqn.imr_ifindex = ifindex;
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn, sizeof(mreqn)) ==
        -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (loopback != 0) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loopback,
                   sizeof(loopback)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  if (ttl != -1) {
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl)) == -1) {
      std::cerr << "setsockopt: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(argv[optind], errbuf);
  if (handle == nullptr) {
    std::cerr << "pcap_open: " << errbuf << std::endl;
    return 1;
  }

  pcap_pkthdr header;
  const u_char *p;
  timeval tv = {0, 0};
  while ((p = pcap_next(handle, &header))) {
    if (header.len != header.caplen) {
      std::cerr << "Header wrong size" << std::endl;
      continue;
    }

    // Removed check for ethernet frame, assumes we're playing back
    // something that was sent to loopback.
    //
    // TODO FIXME Make this detect ethernet vs. loopback.
    //
    auto ip = reinterpret_cast<const iphdr *>(p + 4);
    if (ip->version != 4) {
      std::cerr << "Not IPv4" << std::endl;
      continue;
    }
    if (ip->protocol != IPPROTO_UDP) {
      std::cerr << "Not UDP" << std::endl;
      continue;
    }
    auto udp = reinterpret_cast<const udphdr *>(p + 4 +
                                                ip->ihl * 4);

    if (tv.tv_sec == 0) {
      tv = header.ts;
    }
    timeval diff;
    timersub(&header.ts, &tv, &diff);
    tv = header.ts;
    usleep((diff.tv_sec * 1000000 + diff.tv_usec) * speed);

    ssize_t len = ntohs(udp->len) - 8;
    const u_char *d = &p[4 + ip->ihl * 4 + sizeof(udphdr)];

    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = udp->dest;
    addr.sin_addr = {ip->daddr};
    auto n = sendto(fd, d, len, 0, reinterpret_cast<sockaddr *>(&addr),
                    sizeof(addr));
    if (n != len) {
      std::cerr << "sendto: " << strerror(errno) << std::endl;
      return 1;
    }
  }

  return 0;
}
