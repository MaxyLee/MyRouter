#include "router.h"
#include "rip.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <vector>
using namespace std;


/*
  RoutingTable Entry 的定义如下：
  typedef struct {
    uint32_t addr; // 大端序，IPv4 地址
    uint32_t len; // 小端序，前缀长度
    uint32_t if_index; // 小端序，出端口编号
    uint32_t nexthop; // 大端序，下一跳的 IPv4 地址
  } RoutingTableEntry;

  约定 addr 和 nexthop 以 **大端序** 存储。
  这意味着 1.2.3.4 对应 0x04030201 而不是 0x01020304。
  保证 addr 仅最低 len 位可能出现非零。
  当 nexthop 为零时这是一条直连路由。
  你可以在全局变量中把路由表以一定的数据结构格式保存下来。
*/

std::vector<RoutingTableEntry> routers;

int getIndex(uint32_t addr, uint32_t len){
  int index = -1;
  for(int i = 0;i < routers.size();i++) {
    if(routers.at(i).addr == addr && routers.at(i).len == len)
      return i;
  }
  return index;
}

int match(uint32_t addr) {

  int maxlen = -1;
  int maxindex=-1;

  for(int i = 0;i < routers.size();i++) {
      RoutingTableEntry rt = routers.at(i);

      int len = (int)rt.len;
      uint32_t mask = 0;
      for(uint32_t j = 0;j < len;j++) {
        mask = (mask << 1) + 1;
      }

      if((addr & mask) == (rt.addr & mask)) {
        if(maxlen < len) {
          maxlen = len;
          maxindex = i;
        }
      }
    }

  return maxindex;
}


/**
 * @brief 插入/删除一条路由表表项
 * @param insert 如果要插入则为 true ，要删除则为 false
 * @param entry 要插入/删除的表项
 * 
 * 插入时如果已经存在一条 addr 和 len 都相同的表项，则替换掉原有的。
 * 删除时按照 addr 和 len 匹配。
 */
void update(bool insert, RoutingTableEntry entry) {
  // TODO:
  if(insert) {
    int index = getIndex(entry.addr,entry.len);
    if(index == -1)
      routers.push_back(entry);
    else {
      routers.at(index).if_index = entry.if_index;
      routers.at(index).nexthop = entry.nexthop;
      routers.at(index).metric = entry.metric;
    }
  } else {
    int index = getIndex(entry.addr,entry.len);
    routers.erase(routers.begin() + index);
  }
}

/**
 * @brief 进行一次路由表的查询，按照最长前缀匹配原则
 * @param addr 需要查询的目标地址，大端序
 * @param nexthop 如果查询到目标，把表项的 nexthop 写入
 * @param if_index 如果查询到目标，把表项的 if_index 写入
 * @return 查到则返回 true ，没查到则返回 false
 */
bool query(uint32_t addr, uint32_t *nexthop, uint32_t *if_index) {
  // TODO:

  int index = match(addr);
  if(index == -1)
    return false;
  
  *nexthop = routers.at(index).nexthop;
  *if_index = routers.at(index).if_index;

  return true;
}

void fillResp(RipPacket *resp, uint32_t dst_addr, uint32_t if_index) {
  resp->command = 2;
  int cnt = 0;
  for(int i = 0;i < routers.size();i++){
    if((dst_addr & 0x00ffffff) != routers.at(i).addr && if_index != routers.at(i).if_index) {
      printf("fill resp, dst_addr:%08x  addr:%08x\n", dst_addr, routers.at(i).addr);
      resp->entries[cnt].addr = routers.at(i).addr;
      uint32_t len = routers.at(i).len;
      uint32_t mask = 0;
      for(int j = 0;j < len;j++)
        mask = (mask << 1) + 0x1;// big endian
      resp->entries[cnt].mask = mask;
      resp->entries[cnt].nexthop = routers.at(i).nexthop;
      resp->entries[cnt].metric = routers.at(i).metric;//not sure
      cnt++;
    }
  }
  resp->numEntries = cnt;
}

void updateRouterTable(RipEntry entry, uint32_t if_index) {
  RoutingTableEntry RTEntry;
  RTEntry.addr = entry.addr;
  RTEntry.nexthop = entry.nexthop;
  uint32_t mask = entry.mask;
  uint32_t len = 0;
  printf("update, mask:%08x\n", mask);
  while((mask & 1) != 0) {
    len++;
    mask >>= 1;
  }
  printf("update, len:%d\n", len);
  RTEntry.len = len;
  RTEntry.if_index = if_index;
  RTEntry.metric = entry.metric;

  int index = getIndex(entry.addr, len);
  if(index >= 0) {
    //exist
    printf("update, exist\n");
    if(RTEntry.metric + 1 < routers.at(index).metric) {
      printf("update, newMetric < metric\n");
      RTEntry.metric++;
      update(true, RTEntry);
    }
  } else {
    //not exist
    //but why do not metric add 1 ???
    printf("update, not exist\n");
    RTEntry.metric++;
    update(true, RTEntry);
  }
}

void DEBUG_printRouterTable() {
  printf("f**king debugging babe?\n#########################################\n");
  for(int i = 0;i < routers.size();i++) {
    RoutingTableEntry RTEntry = routers.at(i);
    printf("entry %d:\n", i);
    printf("addr:%08x\nlen:%d\nif_index:%d\nnexthop:%08x\nmetric:%08x\n--------------------------------\n", RTEntry.addr, RTEntry.len, RTEntry.if_index, RTEntry.nexthop, RTEntry.metric);
  }
  printf("#########################################\n");
}