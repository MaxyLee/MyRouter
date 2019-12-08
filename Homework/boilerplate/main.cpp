#include "router_hal.h"
#include "rip.h"
#include "router.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define protocolUDP 0x11
#define protocolICMP 0x1
#define ICMPtypeTimeExceeded 11
#define ICMPcodeTimeExceeded 0
#define ICMPtypeDestNetworkUnreachable 3
#define ICMPcodeDestNetworkUnreachable 0

extern bool validateIPChecksum(uint8_t *packet, size_t len);
extern void update(bool insert, RoutingTableEntry entry);
extern bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index);
extern bool forward(uint8_t *packet, size_t len);
extern bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output);
extern uint32_t assemble(const RipPacket *rip, uint8_t *buffer);
extern void fillResp(const RipPacket* resp);
extern void updateRouterTable(RipEntry entry);

uint8_t packet[2048];
uint8_t output[2048];
// 0: 10.0.0.1
// 1: 10.0.1.1
// 2: 10.0.2.1
// 3: 10.0.3.1
// 你可以按需进行修改，注意端序
in_addr_t addrs[N_IFACE_ON_BOARD] = {0x0100000a, 0x0101000a, 0x0102000a, 0x0103000a};

void getIPChecksum(uint8_t* pac);
int getUDPChecksum(uint8_t* pac);
void IPHeader(in_addr_t src_addr, in_addr_t dst_addr, uint16_t totalLength, uint8_t protocol, uint8_t* pac);
int ICMPTimeExceeded(in_addr_t src_addr, in_addr_t dst_addr);
int ICMPDestNetworkUnreachable(in_addr_t src_addr, in_addr_t dst_addr);
int Response(in_addr_t src_addr, in_addr_t dst_addr, uint8_t* pac);

int main(int argc, char *argv[]) {
  int res = HAL_Init(1, addrs);
  if (res < 0) {
    return res;
  }
  
  // Add direct routes
  // For example:
  // 10.0.0.0/24 if 0
  // 10.0.1.0/24 if 1
  // 10.0.2.0/24 if 2
  // 10.0.3.0/24 if 3
  for (uint32_t i = 0; i < N_IFACE_ON_BOARD;i++) {
    RoutingTableEntry entry = {
      .addr = addrs[i], // big endian
      .len = 24, // small endian
      .if_index = i, // small endian
      .nexthop = 0, // big endian, means direct
      .metric = 1
    };
    update(true, entry);
  }

  uint64_t last_time = 0;
  while (1) {
    uint64_t time = HAL_GetTicks();
    if (time > last_time + 30 * 1000) {
      // What to do? <----- send router table every 30 sec
      if(routers.size() > 0) {
        //////////////////////////////////////////////////////////////////////
        for(int i = 0;i < routers.size();i++) { //router in routers
          int length = Response();
          int if_index = routers.at(i).if_index;
          macaddr_t dst_mac;
          HAL_ArpGetMacAddress(if_index, routers.at(i).nexthop, dst_mac);
          HAL_SendIPPacket(if_index, output, length, dst_mac);
        }
      }
      
      time = last_time;
      printf("Timer\n");
    }

    int mask = (1 << N_IFACE_ON_BOARD) - 1;
    macaddr_t src_mac;
    macaddr_t dst_mac;
    int if_index;
    res = HAL_ReceiveIPPacket(mask, packet, sizeof(packet), src_mac,
                                  dst_mac, 1000, &if_index);
    if (res == HAL_ERR_EOF) {
      break;
    } else if (res < 0) {
      return res;
    } else if (res == 0) {
      // Timeout
      continue;
    } else if (res > sizeof(packet)) {
      // packet is truncated, ignore it
      continue;
    }
    // res > 0
    uint8_t version = packet[0] >> 4;
    if(version != 4 || version != 6) {
      printf("Invalid version\n");
    }

    uint8_t TTL = packet[8];
    if(TTL <= 0) {
      printf("Invalid TTL\n");
      continue;
    }

    if (!validateIPChecksum(packet, res)) {
      printf("Invalid IP Checksum\n");
      continue;
    }

    

    in_addr_t src_addr, dst_addr;
    // extract src_addr and dst_addr from packet
    // big endian
    src_addr = (packet[12] << 24) + (packet[13] << 16) + (packet[14] << 8) + packet[15];
    dst_addr = (packet[16] << 24) + (packet[17] << 16) + (packet[18] << 8) + packet[19];

    bool dst_is_me = false;
    for (int i = 0; i < N_IFACE_ON_BOARD;i++) {
      if (memcmp(&dst_addr, &addrs[i], sizeof(in_addr_t)) == 0) {
        dst_is_me = true;
        break;
      }
    }
    // TODO: Handle rip multicast address?

    if (dst_is_me) {
      // TODO: RIP?
      RipPacket rip;
      if (disassemble(packet, res, &rip)) {
        if (rip.command == 1) {
          // request
          int length = Response(dst_addr, src_addr, output);
          // send it back
          HAL_SendIPPacket(if_index, output, length, src_mac);
        } else {
          // response
          // TODO: use query and update
          for(int i = 0;i < rip.numEntries;i++) {
            RipEntry entry = rip.entries[i];
            uint32_t newMetirc = entry.metric + 1;
            if(newMetirc >= 16) {
              //delete this route
              uint32_t len = 32;
              uint32_t mask = entry.mask;
              while((mask & 1) == 0) {
                mask >> 1;
                len--;
              }
              RoutingTableEntry RTEntry = {
                .addr = entry.addr, // big endian
                .len = len, // small endian
                .if_index = 0, // small endian /////////////////////////////////////////////////////idk
                .nexthop = entry.nexthop, // big endian, means direct
                .metric = entry.metric
              };
              update(false, RTEntry);
              // idk how to print ???
              continue;
            }
            updateRouterTable(entry);

          }
        }
      } else {
        // forward
        // beware of endianness
        uint32_t nexthop, dest_if;
        if (query(src_addr, &nexthop, &dest_if)) {
          // found
          macaddr_t dest_mac;
          // direct routing
          if (nexthop == 0) {
            nexthop = dst_addr;
          }
          if (HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac) == 0) {
            // found
            memcpy(output, packet, res);
            // update ttl and checksum
            forward(output, res);
            // TODO: you might want to check ttl=0 case
            uint8_t TTL = output[8];
            if(TTL == 0) {
              //return a ICMP Time Exceeded to sender <----- how to do it ????
              int length = ICMPTimeExceeded(dst_addr, src_addr);
              HAL_SendIPPacket(dest_if, output, length, dest_mac);
              continue;
            }
            HAL_SendIPPacket(dest_if, output, res, dest_mac);
          } else {
            // not found
          }
        } else {
          // not found
          //return a ICMP Destination Network Unreachable to sender <----- how to do it ????
          macaddr_t dest_mac;
          HAL_ArpGetMacAddress(dest_if, nexthop, dest_mac);
          int length = ICMPDestNetworkUnreachable(dst_addr, src_addr);//???
          HAL_SendIPPacket(dest_if, output, length, dest_mac);
        }
      }
    }
  }
  return 0;
}

void getIPChecksum(uint8_t* pac) {
  int IPchecksum = 0;
  int headLength = (pac[0] & 0xf) * 4;
  pac[10] = 0;
  pac[11] = 0;
  for(int i = 0;i < headLength;i++) {
    if(i % 2 == 0) {
      IPchecksum += ((int)pac[i]) << 8;
    } else {
      IPchecksum += (int)pac[i];
    }
  }
  IPchecksum = (IPchecksum >> 16) + (IPchecksum & 0xffff);
  IPchecksum += (IPchecksum >> 16);
  IPchecksum = ~IPchecksum;
  pac[10] = IPchecksum >> 8;
  pac[11] = IPchecksum;
}

int getUDPChecksum(uint8_t* pac) {
  int UDPchecksum = 0;
  uint16_t UDPLength = (((int)pac[24]) << 8) + pac[25];
  for(int i = 12;i < 20;i++) {
    if(i % 2 == 0) {
      UDPchecksum += ((int)pac[i]) << 8;
    } else {
      UDPchecksum += (int)pac[i];
    }
  }
  UDPchecksum += protocolUDP;
  UDPchecksum += UDPLength;
  //UDP header
  for(int i = 20;i < 26;i++) {
    if(i % 2 == 0) {
      UDPchecksum += ((int)pac[i]) << 8;
    } else {
      UDPchecksum += (int)pac[i];
    }
  }
  UDPchecksum = (UDPchecksum >> 16) + (UDPchecksum & 0xffff);
  UDPchecksum += (UDPchecksum >> 16);
  UDPchecksum = ~UDPchecksum;
  return UDPchecksum;
}

void IPHeader(in_addr_t src_addr, in_addr_t dst_addr, uint16_t totalLength, uint8_t protocol, uint8_t* pac) {
  //this function fill a IP header 
  //version = 4, header length = 5
  pac[0] = 0x45;
  //type of service = 0
  pac[1] = 0x00;
  //total length
  pac[2] = totalLength >> 8;
  pac[3] = totalLength;
  //id = 0
  pac[4] = 0x00;
  pac[5] = 0x00;
  //flags = 0, fragmented offset = 0
  pac[6] = 0x00;
  pac[7] = 0x00;
  //time to live = 1
  pac[8] = 0x01;
  //protocol = 17(UDP)
  pac[9] = protocol;
  //source address = src_addr
  pac[12] = src_addr >> 24;
  pac[13] = src_addr >> 16;
  pac[14] = src_addr >> 8;
  pac[15] = src_addr;
  //destination address = dst_addr
  pac[16] = dst_addr >> 24;
  pac[17] = dst_addr >> 16;
  pac[18] = dst_addr >> 8;
  pac[19] = dst_addr;
  getIPChecksum(pac);
}

int ICMPTimeExceeded(in_addr_t src_addr, in_addr_t dst_addr) {
  uint16_t packetHeaderLength = (packet[0] & 0xf) * 4;
  uint16_t ICMPLength = 8 + packetHeaderLength + 8;
  uint16_t totalLength = 20 + ICMPLength;
  //IP header
  IPHeader(src_addr, dst_addr, totalLength, protocolICMP, output);
  //ICMP header
  output[20] = ICMPtypeTimeExceeded;
  output[21] = ICMPcodeTimeExceeded;
  for(int i = 0;i < 6;i++)
    output[22 + i] = 0x0;
  //source packet IP header and 8 bytes
  memcpy(output + 20 + 8, packet, size_t(packetHeaderLength));

  output[22] = 0;
  output[23] = 0;
  int checksum = 0;
  for(int i = 0; i < ICMPLength;i++) {
    if(i % 2 == 0) {
      checksum += ((int)output[20 + i]) << 8;
    } else {
      checksum += (int)output[20 + i];
    }
  }
  checksum = (checksum >> 16) + (checksum & 0xffff);
  checksum += (checksum >> 16);
  checksum = ~checksum;
  output[22] = checksum >> 8;
  output[23] = checksum;
  return (int)totalLength;
}

int ICMPDestNetworkUnreachable(in_addr_t src_addr, in_addr_t dst_addr) {
  uint16_t packetHeaderLength = (packet[0] & 0xf) * 4;
  uint16_t ICMPLength = 8 + packetHeaderLength + 8;
  uint16_t totalLength = 20 + ICMPLength;
  //IP header
  IPHeader(src_addr, dst_addr, totalLength, protocolICMP, output);
  //ICMP header
  output[20] = ICMPtypeDestNetworkUnreachable;
  output[21] = ICMPcodeDestNetworkUnreachable;
  for(int i = 0;i < 6;i++)
    output[22 + i] = 0x0;
  //source packet IP header and 8 bytes
  memcpy(output + 20 + 8, packet, size_t(packetHeaderLength));

  output[22] = 0;
  output[23] = 0;
  int checksum = 0;
  for(int i = 0; i < ICMPLength;i++) {
    if(i % 2 == 0) {
      checksum += ((int)output[20 + i]) << 8;
    } else {
      checksum += (int)output[20 + i];
    }
  }
  checksum = (checksum >> 16) + (checksum & 0xffff);
  checksum += (checksum >> 16);
  checksum = ~checksum;
  output[22] = checksum >> 8;
  output[23] = checksum;
  return (int)totalLength;
}

int Response(in_addr_t src_addr, in_addr_t dst_addr, uint8_t* pac) {
  RipPacket resp;
  fillResp(&resp);
  // UDP
  // port = 520
  // source port
  pac[20] = 0x02;
  pac[21] = 0x08;
  // destination port
  pac[22] = 0x02;
  pac[23] = 0x08;
  // ...
  // RIP
  uint32_t rip_len = assemble(&resp, &pac[20 + 8]);
  //total length of IP packet
  uint16_t totalLength = rip_len + 28;
  //fill IP header
  IPHeader(src_addr, dst_addr, totalLength, protocolUDP, pac);
  //length of UDP packet
  uint16_t UDPLength = rip_len + 8;
  pac[24] = UDPLength >> 8;
  pac[25] = UDPLength;
  // checksum calculation for ip and udp <---- IP checksum already calculated before
  //UDP checksum
  int UDPchecksum = getUDPChecksum(output);
  pac[26] = UDPchecksum >> 8;
  pac[27] = UDPchecksum;
  return (int)totalLength;
}