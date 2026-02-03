#include "trie.h"

int get_mask_len(uint32_t mask) {
    int len = 0;
    uint32_t m = ntohl(mask); 
    
    // Count 1s bit from left
    while (m & 0x80000000) {
        len++;
        m <<= 1;
    }
    return len;
}

struct trie_node *createNode() {
    struct trie_node *node = (struct trie_node *)malloc(sizeof(struct trie_node));
    
    // Init Empty Node
    node->children[0] = NULL;
    node->children[1] = NULL;
    node->entry = NULL;

    return node;
}

void insert(struct trie_node *root, struct route_table_entry *entry) {
    struct trie_node *current = root;

    int mask_len = get_mask_len(entry->mask);
    uint32_t prefix = ntohl(entry->prefix);
    
    // Iterate through mask length
    for (int i = 0; i < mask_len; i++) {
        // Get i-th bit of IP
        int index = (prefix >> (31 - i)) & 0x1;
        // Create Node if necessary
        if (current->children[index] == NULL) {
            current->children[index] = createNode();
        }
        current = current->children[index];
    }
    // Put the entry on the last node
    current->entry = entry;
}

void free_trie(struct trie_node *root) {
    // Stop case
    if (root == NULL) {
        return;
    }

    // Free Children
    free_trie(root->children[0]);
    free_trie(root->children[1]);

    // Free Entry
    if (root->entry != NULL) {
        free(root->entry);
        root->entry = NULL;
    }

    // Free root
    free(root);
}