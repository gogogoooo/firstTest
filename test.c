#include <pcap.h>  
#include <time.h>  
#include <stdlib.h>  
#include <stdio.h>  
#include <arpa/inet.h> 
#include <unistd.h>
#include <libnet.h> 

struct ether_header  
{  
    unsigned char ether_dhost[6];   //目的mac  
    unsigned char ether_shost[6];   //源mac  
    unsigned short ether_type;      //以太网类型  
};  
int sendArpRequest() {
printf("arp in\n");
    libnet_t *handle;        /* Libnet句柄 */
    int packet_size;
    char *device = "eth0";   /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备 */
    char *src_ip_str = "192.168.30.91";       /* 源IP地址字符串 */
    char *dst_ip_str = "192.168.30.90";        /* 目的IP地址字符串 */
    unsigned char src_mac[6] = {0x00, 0x0c, 0x29, 0x8d, 0x8c, 0xe0};/* 源MAC */
    unsigned char dst_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};/* 目的MAC,广播地址 */
    /* 接收方MAC,ARP请求目的就是要询问对方MAC,所以这里填写0 */
    unsigned char rev_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    u_int32_t dst_ip, src_ip;              /* 网路序的目的IP和源IP */
    char error[LIBNET_ERRBUF_SIZE];        /* 出错信息 */
    libnet_ptag_t arp_proto_tag, eth_proto_tag;

    /* 把目的IP地址字符串转化成网络序 */
    dst_ip = libnet_name2addr4(handle, dst_ip_str, LIBNET_RESOLVE);
    /* 把源IP地址字符串转化成网络序 */
    src_ip = libnet_name2addr4(handle, src_ip_str, LIBNET_RESOLVE);

    if ( dst_ip == -1 || src_ip == -1 ) {
        printf("ip address convert error\n");
        exit(-1);
    };
    /* 初始化Libnet,注意第一个参数和TCP初始化不同 */
    if ( (handle = libnet_init(LIBNET_LINK_ADV, device, error)) == NULL ) {
        printf("libnet_init: error [%s]\n", error);
        exit(-2);
    };

    /* 构造arp协议块 */
    arp_proto_tag = libnet_build_arp(
                ARPHRD_ETHER,        /* 硬件类型,1表示以太网硬件地址 */ 
                ETHERTYPE_IP,        /* 0x0800表示询问IP地址 */ 
                6,                   /* 硬件地址长度 */ 
                4,                   /* IP地址长度 */ 
                ARPOP_REQUEST,       /* 操作方式:ARP请求 */ 
                src_mac,             /* source MAC addr */ 
                (uint8_t *)&src_ip, /* src proto addr */ 
                rev_mac,             /* dst MAC addr */ 
                (uint8_t *)&dst_ip, /* dst IP addr */ 
                NULL,                /* no payload */ 
                0,                   /* payload length */ 
                handle,              /* libnet tag */ 
                0                    /* Create new one */
    );
    if (arp_proto_tag == -1)    {
        printf("build IP failure\n");
        exit(-3);
    };

    /* 构造一个以太网协议块
    You should only use this function when 
    libnet is initialized with the LIBNET_LINK interface.*/
    eth_proto_tag = libnet_build_ethernet(
        dst_mac,         /* 以太网目的地址 */
        src_mac,         /* 以太网源地址 */
        ETHERTYPE_ARP,   /* 以太网上层协议类型，此时为ARP请求 */
        NULL,            /* 负载，这里为空 */ 
        0,               /* 负载大小 */
        handle,          /* Libnet句柄 */
        0                /* 协议块标记，0表示构造一个新的 */ 
    );
    if (eth_proto_tag == -1) {
        printf("build eth_header failure\n");
        return (-4);
    };

    packet_size = libnet_write(handle);    /* 发送已经构造的数据包*/

    libnet_destroy(handle);                /* 释放句柄 */
printf("arp out\n");

    return (0);
}
  
/*******************************回调函数************************************/  
void ethernet_protocol_callback(unsigned char *argument,const struct pcap_pkthdr *packet_heaher,const unsigned char *packet_content)  
{  
    unsigned char *mac_string;              //  
    struct ether_header *ethernet_protocol;  
    unsigned short ethernet_type;           //以太网类型  
    printf("----------------------------------------------------\n");  
    printf("%s\n", ctime((time_t *)&(packet_heaher->ts.tv_sec))); //转换时间  
    ethernet_protocol = (struct ether_header *)packet_content;  
      
    mac_string = (unsigned char *)ethernet_protocol->ether_shost;//获取源mac地址  
    printf("Mac Source Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));  
    mac_string = (unsigned char *)ethernet_protocol->ether_dhost;//获取目的mac  
    printf("Mac Destination Address is %02x:%02x:%02x:%02x:%02x:%02x\n",*(mac_string+0),*(mac_string+1),*(mac_string+2),*(mac_string+3),*(mac_string+4),*(mac_string+5));  
      
    ethernet_type = ntohs(ethernet_protocol->ether_type);//获得以太网的类型  
    printf("Ethernet type is :%04x\n",ethernet_type);  
    switch(ethernet_type)  
    {  
        case 0x0800:printf("The network layer is IP protocol\n");break;//ip  
        case 0x0806:printf("The network layer is ARP protocol\n");break;//arp  
        case 0x0835:printf("The network layer is RARP protocol\n");break;//rarp  
        default:break;  
    }  
    sendArpRequest();
    usleep(800*1000);  
}  
  
void getPacket(u_char * arg, const struct pcap_pkthdr * pkthdr, const u_char * packet)  
{  
  int * id = (int *)arg;  
    
  printf("id: %d\n", ++(*id));  
  printf("Packet length: %d\n", pkthdr->len);  
  printf("Number of bytes: %d\n", pkthdr->caplen);  
  printf("Recieved time: %s", ctime((const time_t *)&pkthdr->ts.tv_sec));   
    
  int i;  
  for(i=0; i<pkthdr->len; ++i)  
  {  
    printf(" %02x", packet[i]);  
    if( (i + 1) % 16 == 0 )  
    {  
      printf("\n");  
    }  
  }  
    
  printf("\n\n");  
}  
 

int main(int argc, char ** argv)
{
	pcap_t *pcap_handle;
	char   *filter_str   = "udp or tcp";
	char   err_buf[1024] = {0};
	struct bpf_program filter;
	
	if(1 == argc) {
		char *dev_name;
		dev_name = pcap_lookupdev(err_buf);
		if(dev_name)
		{
			printf("open device(%s) success.\n", dev_name);
		}
		else
		{
			printf("open device(%s) failed.\n", err_buf);
			exit(1);
		}

		pcap_handle = pcap_open_live(dev_name, 65535, 1, 0, err_buf);
		if(!pcap_handle)
		{
			printf("error: pcap_open_live(): %s\n", err_buf);
			exit(1);
		}
	}
	else
	{
		char *file = argv[1];
	
		pcap_handle = pcap_open_offline(file,err_buf);
		if(pcap_handle == NULL) {
			printf("open offline file(%s) failed\n",file);
		}
		printf("open pcap file :%s\n",file);
	}	
#if 0
	pcap_compile(pcap_handle,&filter,filter_str,1,0);
	printf("compile\n");
	int ret = pcap_setfilter(pcap_handle,&filter);
	if(0 != ret){
		printf("set filter failed\n");
	}
	printf("set filter success\n");
#endif
	int id = 0;
	pcap_loop(pcap_handle,9,ethernet_protocol_callback,(u_char*)&id);
	return 0;
}
