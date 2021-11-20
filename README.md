/**
 * This document shows how to extract data from skbuff kernel structure.
 * We will be creating kernel module printSKB.ko for getting raw packet data.
 * NOTE: Since millions of packet are transferring through different sockets, we'll apply tcp filter. 
 * Otherwise it will print every packet.
 * This kernel module is written and tested in ubuntu 16.04 (kernel 4.15.0-45). Please sync nefilter functions with latest versions
 * of kernel if you are working with higher kernel versions.
 */

Step 1: 

Include all required headers.
```
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/inet.h>
```

//These headers are required for running our kernel module. Better go through all of these for better understanding of functions.


Step 2:

Create structure objects for necessary structures.
```
static struct nf_hook_ops nfho;     // net filter hook option struct
struct sk_buff *sock_buff;          // socket buffer used in linux kernel
struct udphdr *tcp_header;          // tcp header struct
struct iphdr *ip_header;            // ip header struct
struct ethhdr *mac_header;          // mac header struct
```
Step 3:

Create function netfilter_hook_func()

```
unsigned int netfilter_hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    sock_buff = skb;
    ip_header = (struct iphdr *)skb_network_header(sock_buff); //grab network header using accessor
    mac_header = (struct ethhdr *)skb_mac_header(sock_buff);

    if(!sock_buff) { return NF_DROP; }

    if (ip_header->protocol==IPPROTO_TCP) { 
        printk(KERN_INFO "TCP Packet Seen.\n");     
        printk(KERN_INFO "src_ip: %pI4 \n", &ip_header->saddr);
        printk(KERN_INFO "dst_ip: %pI4\n", &ip_header->daddr);
        print_skbuff_packet(sock_buff);                                    //This function prints the skbuffer
    }
    return NF_ACCEPT;

}

```
Step 4:

Create print_skbuff_packet()

//Taken this function from internet.
```
print_skbuff_packet(struct sk_buff *skb)
{
    size_t len;
    int rowsize = 16;
    int i, l, linelen, remaining;
    int li = 0;
    uint8_t *data, ch;

    printk("Packet sk_buff data:\n");
    data = (uint8_t *) skb_mac_header(skb);

    if (skb_is_nonlinear(skb)) 
    {
        len = skb->data_len;

    } else 
    {
        len = skb->len;
    }

    remaining = len;
    for (i = 0; i < len; i += rowsize) {
        printk("%06d\t", li);

        linelen = min(remaining, rowsize);
        remaining -= rowsize;

        for (l = 0; l < linelen; l++) {
        ch = data[l];
        printk(KERN_CONT "%02X ", (uint32_t) ch);

    }

        data += linelen;
        li += 10;

        printk(KERN_CONT "\n");

    }

}

```
Step 5:

Write init and exit function for initializing our kernel module.
```
int __init init_module()
{
    nfho.hook = hook_func;
    nfho.hooknum = NF_IP_POST_ROUTING;  //  capture TCP reply packets, use NF_IP_PRE_ROUTING = 0 for requesting packets.
    nfho.pf = PF_INET; //IPV4 packets
    nfho.priority = NF_IP_PRI_FIRST;   //set to highest priority over all other hook functions
    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "---------------------------------------\n");
    printk(KERN_INFO "printSKB started\n");
    return 0;

}

void __exit cleanup_module()
{
    printk(KERN_INFO "Cleaning printSKB module.\n");
    nf_unregister_net_hook(&init_net, &nfho);
}

```