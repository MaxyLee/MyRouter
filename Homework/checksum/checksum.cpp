#include <stdint.h>
#include <stdlib.h>
/**
 * @brief 进行 IP 头的校验和的验证
 * @param packet 完整的 IP 头和载荷
 * @param len 即 packet 的长度，单位是字节，保证包含完整的 IP 头
 * @return 校验和无误则返回 true ，有误则返回 false
 */
bool validateIPChecksum(uint8_t *packet, size_t len) {
  // TODO:
  int headLength = (int)(packet[0]&0xf) << 2;
  int i = 0;
  int sum = 0;
  unsigned short answer = 0;
  for(i = 0;i < headLength;i++) {
    if(i%2 == 0)
      sum += ((int)packet[i]) << 8;
    else
      sum += (int)packet[i];
  }
  sum = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  if(answer == 0x0000)
    return true;
  return false;
}