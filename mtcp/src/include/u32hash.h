#ifndef U32HASH_H
#define U32HASH_H
#include <stdint.h>
#include <stdlib.h>
#include "config.h"


#define POOL_SIZE SBUFF_ELE_COUNT 
#define TABLE_SIZE (POOL_SIZE<<1)
#define true 1
#define false 0

#define DELETED_VALUE UINT16_MAX  // 使用 uint16_t 的最大值作为删除标记


typedef struct HashNode {
    uint32_t key;
    uint16_t value;
    struct HashNode* next;
} HashNode;

typedef struct {
    HashNode* buckets[TABLE_SIZE];  // 哈希桶
    HashNode node_pool[POOL_SIZE];  // 节点池
    HashNode* free_nodes;           // 空闲节点链表
    uint32_t size;                    // 当前使用的节点数
} HashTable;

void hash_init(HashTable *table);
uint16_t hash_insert(HashTable* table, uint32_t key, uint16_t value);
uint16_t hash_lookup(const HashTable* table, uint32_t key) ;
uint16_t hash_delete(HashTable* table, uint32_t key);


#endif