# Trie Based Algorithms for IP Lookup

0, Binary Trie
1, Disjoint Prefix Binary Trie
2, Path Compressed Trie
3, Multi Bit Trie
4, Multi Bit Trie with Leaf Pushing
5, Level Compression Trie

6, Binary Search on Prefix Lengths


0, Binary Trie
Using recurssion to carry the current ancestor's verdict (not -1) to child nodes. 
1), If neither of children is NULL, if the node is a prefix node, then update the current ancestor's verdict to be the node's verdict, and recurrsion on the children. 
2), If both children are NULL, return. 
3), If only one of them is NULL, then create a node with the current ancestor's verdict for replacing the NULL.  

1, Disjoint Prefix Binary Trie


1. This reference code provides the following functionality:
   - Read packets from an offline packet trace (in this case, trace.dump)
   - Lookup each packet's IP in a routing table (in this case, routing_table.txt or routing_table2.txt)

2. To compile the ip-lookup-offline code, type in the command line:
   $ g++ ip_lookup_offline.c -o a.out -lpcap
   (Of course you can choose another output file name.)

3. To run ip-lookup-offline, type in the command line:
   $ ./a.out [file name of packet trace] [file name of routing table]
   For example,
   $ ./a.out trace.dump routing_table.txt

4. To compile the routing table generator code, type in the command line:
   $ g++ routing_table_gen.cpp -o b.out

5. To run routing table generator, type in the command line:
   $ ./b.out [# of rules to generator] [# of possible port numbers] > [file name of routing table]
   For example,
   $ ./b.out 100000 100 > routing_table.txt
   , which generates 100000 rules, with 100 possible port numbers (1-100), and write to routing_table.txt
