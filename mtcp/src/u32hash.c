#include "u32hash.h"
#include <string.h>
#include <stdio.h>

// 初始化哈希表
void hash_init(HashTable *table)
{
    // 清空哈希桶
    memset(table->buckets, 0, sizeof(HashNode *) * TABLE_SIZE);

    // 初始化节点池，将所有节点连接成一个空闲链表
    for (size_t i = 0; i < POOL_SIZE - 1; i++)
    {
        table->node_pool[i].next = &table->node_pool[i + 1];
    }
    table->node_pool[POOL_SIZE - 1].next = NULL;

    // 设置空闲节点链表头
    table->free_nodes = &table->node_pool[0];
    table->size = 0;
}

// 从节点池获取一个节点
static HashNode *get_free_node(HashTable *table)
{
    if (!table->free_nodes)
    {
        return NULL; // 节点池已空
    }

    HashNode *node = table->free_nodes;
    table->free_nodes = node->next;
    return node;
}

// 返回节点到节点池
static void return_node(HashTable *table, HashNode *node)
{
    node->next = table->free_nodes;
    table->free_nodes = node;
}

// 哈希函数
static inline size_t hash_function(uint32_t key)
{
    // key = ((key >> 16) ^ key) * 0x45d9f3b;
    // key = ((key >> 16) ^ key) * 0x45d9f3b;
    // key = (key >> 16) ^ key;
    // return key & (TABLE_SIZE - 1);
    // 使用乘法散列法
    const uint64_t a = 2654435769ULL; // 黄金分割比近似值 (2^32 * 0.618033988...)
    return ((key * a) >> 32) & (TABLE_SIZE - 1);
}

// 插入元素
uint16_t hash_insert(HashTable *table, uint32_t key, uint16_t value)
{
    uint16_t index = hash_function(key);
    // printf("insert beform  key(%u) value(%d) index(%d)\n", key, value, index);
    // 检查是否已存在
    HashNode *current = table->buckets[index];
    while (current)
    {
        if (current->key == key)
        {
            printf("error key is exist:  key(%d) value(%d) index(%d)\n", key, value, index);
            exit(0);
            return false; // 键已存在
        }
        current = current->next;
    }

    // 获取新节点
    HashNode *new_node = get_free_node(table);
    if (!new_node)
    {
        printf("error new_node = NULL:  key(%d) value(%d) index(%d)\n", key, value, index);
        exit(0);
        return false; // 节点池已满
    }

    // 初始化新节点
    new_node->key = key;
    new_node->value = value;
    new_node->next = table->buckets[index];

    // 插入到链表头部
    table->buckets[index] = new_node;
    table->size++;
    // printf("insert key(%d) value(%d) index(%d)\n", key, value, index);
    return true;
}

// 查找元素
uint16_t hash_lookup(const HashTable *table, uint32_t key)
{
    uint16_t index = hash_function(key);
    // printf("lookup key(%u) index(%d)\n", key, index);
    HashNode *current = table->buckets[index];

    while (current)
    {
        if (current->key == key)
        {
            return current->value;
        }
        current = current->next;
    }
    return UINT16_MAX;
}

// 删除元素
uint16_t hash_delete(HashTable *table, uint32_t key)
{
    size_t index = hash_function(key);
    HashNode *current = table->buckets[index];
    HashNode *prev = NULL;

    while (current)
    {
        if (current->key == key)
        {
            if (prev)
            {
                prev->next = current->next;
            }
            else
            {
                table->buckets[index] = current->next;
            }
            return_node(table, current);
            table->size--;
            return true;
        }
        prev = current;
        current = current->next;
    }
    return false;
}

// 更新元素值
uint16_t hash_update(HashTable *table, uint32_t key, uint16_t new_value)
{
    size_t index = hash_function(key);
    HashNode *current = table->buckets[index];

    while (current)
    {
        if (current->key == key)
        {
            current->value = new_value;
            return true;
        }
        current = current->next;
    }
    return false;
}