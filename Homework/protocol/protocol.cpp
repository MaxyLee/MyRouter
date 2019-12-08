#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
  在头文件 rip.h 中定义了如下的结构体：
  #define RIP_MAX_ENTRY 25
  typedef struct {
    // all fields are big endian
    // we don't store 'family', as it is always 2(response) and 0(request)
    // we don't store 'tag', as it is always 0
    uint32_t addr;
    uint32_t mask;
    uint32_t nexthop;
    uint32_t metric;
  } RipEntry;

  typedef struct {
    uint32_t numEntries;
    // all fields below are big endian
    uint8_t command; // 1 for request, 2 for response, otherwsie invalid
    // we don't store 'version', as it is always 2
    // we don't store 'zero', as it is always 0
    RipEntry entries[RIP_MAX_ENTRY];
  } RipPacket;

  你需要从 IPv4 包中解析出 RipPacket 结构体，也要从 RipPacket 结构体构造出对应的 IP 包
  由于 Rip 包结构本身不记录表项的个数，需要从 IP 头的长度中推断，所以在 RipPacket 中额外记录了个数。
  需要注意这里的地址都是用 **大端序** 存储的，1.2.3.4 对应 0x04030201 。
*/

/**
 * @brief 从接受到的 IP 包解析出 Rip 协议的数据
 * @param packet 接受到的 IP 包
 * @param len 即 packet 的长度
 * @param output 把解析结果写入 *output
 * @return 如果输入是一个合法的 RIP 包，把它的内容写入 RipPacket 并且返回 true；否则返回 false
 * 
 * IP 包的 Total Length 长度可能和 len 不同，当 Total Length 大于 len 时，把传入的 IP 包视为不合法。
 * 你不需要校验 IP 头和 UDP 的校验和是否合法。
 * 你需要检查 Command 是否为 1 或 2，Version 是否为 2， Zero 是否为 0，
 * Family 和 Command 是否有正确的对应关系，Tag 是否为 0，
 * Metric 转换成小端序后是否在 [1,16] 的区间内，
 * Mask 的二进制是不是连续的 1 与连续的 0 组成等等。
 */
bool disassemble(const uint8_t *packet, uint32_t len, RipPacket *output) {
  // TODO:
  if((((int)packet[2])<<8)+packet[3]>len)
    return false;

  if(packet[30] != 0 || packet[31] != 0)
    return false;

  int numofrip = ((((int)packet[2]) << 8) + packet[3] - (packet[0] & 0xf) * 4 - 4) / 20;

  output->numEntries = 0;

  if(!((packet[28] == 0x02 || packet[28] == 0x01) && packet[29] == 0x02))
    return false;

  for(int i = 0;i < numofrip;i++){
    int ripnum = i * 20;
    uint16_t afi = ((int)packet[32 + ripnum] << 8) + packet[33 + ripnum];
    uint32_t metric = ((int)packet[48 + ripnum] << 24) + ((int)packet[49 + ripnum] << 16) + ((int)packet[50 + ripnum] << 8) + packet[51 + ripnum];
    uint32_t mask = ((int)packet[40 + ripnum] << 24) + ((int)packet[41 + ripnum] << 16) + ((int)packet[42 + ripnum] << 8) + packet[43 + ripnum];
    if((packet[28] == 0x02 && afi == 0x0002) || (packet[28] == 0x01 && afi == 0x0000)) {
        if(metric <= 16 && metric >= 1){
          uint8_t s = 0;
          for(int i = 31;i >= 0;i--){
            uint32_t k = 1 << i;
            if(s == 0) {
              if((mask & k) != k)
                s = 1;
            } else if(s == 1) {
              if((mask & k) == k)
                return false;
            }
          }  
            
          int numEntry = output->numEntries;

          output->entries[numEntry].addr = ((int)packet[39 + ripnum] << 24) + ((int)packet[38 + ripnum] << 16) + ((int)packet[37 + ripnum] << 8) + packet[36 + ripnum];
          output->entries[numEntry].mask = ((int)packet[43 + ripnum] << 24) + ((int)packet[42 + ripnum] << 16) + ((int)packet[41 + ripnum] << 8) + packet[40 + ripnum];;
          output->entries[numEntry].metric = ((int)packet[51 + ripnum] << 24) + ((int)packet[50 + ripnum] << 16) + ((int)packet[49 + ripnum] << 8) + packet[48 + ripnum];
          output->entries[numEntry].nexthop = ((int)packet[47 + ripnum] << 24) + ((int)packet[46 + ripnum] << 16) + ((int)packet[45 + ripnum] << 8) + packet[44 + ripnum];
          output->numEntries++; 
        } else
          return false;

    } else
      return false;
      
  }
  
  output->command = packet[28];
  return true;
}

/**
 * @brief 从 RipPacket 的数据结构构造出 RIP 协议的二进制格式
 * @param rip 一个 RipPacket 结构体
 * @param buffer 一个足够大的缓冲区，你要把 RIP 协议的数据写进去
 * @return 写入 buffer 的数据长度
 * 
 * 在构造二进制格式的时候，你需要把 RipPacket 中没有保存的一些固定值补充上，包括 Version、Zero、Address Family 和 Route Tag 这四个字段
 * 你写入 buffer 的数据长度和返回值都应该是四个字节的 RIP 头，加上每项 20 字节。
 * 需要注意一些没有保存在 RipPacket 结构体内的数据的填写。
 */
uint32_t assemble(const RipPacket *rip, uint8_t *buffer) {
  // TODO:
  buffer[0] = rip->command;
  buffer[1] = 2;
  buffer[2] = 0;
  buffer[3] = 0;

  for(int i = 0;i < rip->numEntries;i++){
    RipEntry entry = rip->entries[i];
    int ripnum = i * 20;
    
    if(rip->command == 2) {
      buffer[4 + ripnum] = 0;
      buffer[5 + ripnum] = 2;
    } else {
      buffer[4 + ripnum] = 0;
      buffer[5 + ripnum] = 0;
    }
    buffer[7 + ripnum] = 0;
    buffer[6 + ripnum] = 0;

    //ip address
    buffer[11 + ripnum] = entry.addr >> 24;
    buffer[10 + ripnum] = entry.addr >> 16;
    buffer[9 + ripnum] = entry.addr >> 8;
    buffer[8 + ripnum] = entry.addr;

    //mask
    buffer[15 + ripnum] = entry.mask >> 24;
    buffer[14 + ripnum] = entry.mask >> 16;
    buffer[13 + ripnum] = entry.mask >> 8;
    buffer[12 + ripnum] = entry.mask;

    //nexthop
    buffer[19 + ripnum] = entry.nexthop >> 24;
    buffer[18 + ripnum] = entry.nexthop >> 16;
    buffer[17 + ripnum] = entry.nexthop >> 8;
    buffer[16 + ripnum] = entry.nexthop;

    //metrics
    buffer[23 + ripnum] = entry.metric >> 24;
    buffer[22 + ripnum] = entry.metric >> 16;
    buffer[21 + ripnum] = entry.metric >> 8;
    buffer[20 + ripnum] = entry.metric;

  }
  return 4 + 20 * rip->numEntries;
}