#ifndef TRIE_H
#define TRIE_H

#include <stdbool.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "lib.h"

struct trie_node {
    struct trie_node *children[2];
    struct route_table_entry *entry;
};

extern struct trie_node *createNode();

extern void insert(struct trie_node *root, struct route_table_entry *entry);

extern void free_trie(struct trie_node *root);

#endif