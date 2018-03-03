#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

//#define DEBUG

/* Structure of binary trie node */
struct BtNode{
    BtNode  *left;      /* for 0 */
    BtNode  *right;     /* for 1 */
    int     verdict;
};

/* Initialize binary trie node */
BtNode* init_btnode(){
    BtNode *ret = (BtNode *)malloc(sizeof(BtNode));
    ret->left = NULL;
    ret->right = NULL;
    ret->verdict = -1;
    return ret;
}

/* Clean up binary trie */
void free_bt(BtNode *root){

    if(root->left != NULL){
        free_bt(root->left);
    }
    if(root->right != NULL){
        free_bt(root->right);
    }

    free(root);
}

/* Insert a rule */
void insert_rule(BtNode *root, uint32_t prefix, int prelen, int portnum){
    static int     n_rules = 0;

#ifdef DEBUG
    uint32_t prefix_r = htonl(prefix);
    fprintf(stderr, "Insert rule: %-15s(%08x)/%d    %d\n", 
            inet_ntoa(*(struct in_addr *)&prefix_r), 
            prefix, prelen, portnum);
#endif

    n_rules ++;

    /* default rule: if packet matches none of the rules, 
     * it will match this default rule, i.e. 0.0.0.0/0 */
    if( prelen == 0 ){
        root->verdict = portnum;
        return;
    }

    uint32_t    temp_prefix = prefix;
    BtNode      *curr_node = root;
    for(int i=0 ; i<prelen ; i++){
        int     curr_bit = (temp_prefix & 0x80000000) ? 1 : 0;
        if(curr_bit == 0){
            if(curr_node->left == NULL){
                curr_node->left = init_btnode();
            }
            curr_node = curr_node->left;
        }
        else{
            if(curr_node->right == NULL){
                curr_node->right = init_btnode();
            }
            curr_node = curr_node->right;
        }
        temp_prefix = temp_prefix << 1;
    }

    if( curr_node->verdict != -1 ){
        fprintf(stderr, "Error: Rule #%d - overwriting a previous rule!! \n", n_rules);
    }
    curr_node->verdict = portnum;
}

/* Look up an IP address (represented in a uint32_t) */
int lookup_ip(BtNode *root, uint32_t ip){
    uint32_t    temp_ip = ip;
    BtNode      *curr_node = root;
    int         curr_verdict = root->verdict;
    int         curr_bit = 0;

    while(1){
        curr_bit = (temp_ip & 0x80000000) ? 1 : 0;
        if(curr_bit == 0){
            if(curr_node->left == NULL)     return curr_verdict;
            else                            curr_node = curr_node->left;
        }
        else{
            if(curr_node->right == NULL)    return curr_verdict;
            else                            curr_node = curr_node->right;
        }

        /* update verdict if current node has an non-empty verdict */
        curr_verdict = (curr_node->verdict == -1) ? curr_verdict : curr_node->verdict;
        temp_ip = temp_ip << 1;
    }
}

/* leaf push function to transform a Binary Trie to a disjoint prefix binary trie*/
void leaf_push(BtNode *node, int curr_ancestor_verdict){
	if(node->verdict >= 0){
		curr_ancestor_verdict = node->verdict;
	}
	if(node->left == NULL && node->right == NULL){
		return;
	}else if(node->left != NULL && node->right != NULL){
		leaf_push(node->left, curr_ancestor_verdict);
		leaf_push(node->right, curr_ancestor_verdict);
	}else{
		if(node->left == NULL){
			if(curr_ancestor_verdict >= 0){
				node->left = init_btnode();
				node->left->verdict = curr_ancestor_verdict;
			}
		    leaf_push(node->right, curr_ancestor_verdict);	
		}else{
			if(curr_ancestor_verdict >= 0){
				node->right = init_btnode();
				node->right->verdict = curr_ancestor_verdict;
			}
			leaf_push(node->left, curr_ancestor_verdict);
		}
	}
}
/* transform binary trie to disjoint prefix binary trie*/
//DbtNodeInternal* = trans_bt2dbt(BtNode *bt_root){
void trans_bt2dbt(BtNode *bt_root){
	//DbtNodeInternal *ret = init_dbtnodeinternal();
    int curr_ancestor_verdict = bt_root->verdict;
	leaf_push(bt_root, curr_ancestor_verdict);
}

