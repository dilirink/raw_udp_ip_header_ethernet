//sudo tcpdump -i lo udp port 8081 -XX -vvv   sudo tcpdump udp port 8081 -XX -vvv ///  sudo tcpdump -i lo udp port 8082 -XX -vvv
//wireshark  ip.src == 192.168.0.10 and ip.dst == 192.168.0.87 and udp 

#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if.h> // if_nametoindex
#include <linux/if_packet.h>
#include <net/ethernet.h> /* the L2 protocols */


#define SOURCE_IP "192.168.0.10" //источник назначения
#define SOURCE_PORT 8081
#define DESTINATION_IP "192.168.0.87" //пункт назначение
#define DESTINATION_PORT 4294
#define SIZE 128
#define ETHER "wlan0"
//извините но я скопипастил у вас этот кусок ибо это жесть -_-
static unsigned short csum(unsigned short* addr, int len)//извините но я скопипастил у вас этот кусок ибо это жесть -_-
{
	int nleft = len;//извините но я скопипастил у вас этот кусок ибо это жесть -_-
	int sum = 0;//извините но я скопипастил у вас этот кусок ибо это жесть -_-
	unsigned short* w = addr;//извините но я скопипастил у вас этот кусок ибо это жесть -_-
	unsigned short answer = 0;//извините но я скопипастил у вас этот кусок ибо это жесть -_-

	while(nleft > 1) {//извините но я скопипастил у вас этот кусок ибо это жесть -_-
		sum += *w ++;//извините но я скопипастил у вас этот кусок ибо это жесть -_-
		nleft -= 2;//извините но я скопипастил у вас этот кусок ибо это жесть -_-
	}//извините но я скопипастил у вас этот кусок ибо это жесть -_-

	if (nleft == 1) {//извините но я скопипастил у вас этот кусок ибо это жесть -_-
		*(unsigned char*) (&answer) = *(unsigned char*) w;
		sum += answer;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	answer = ~sum;

	return answer;	
}
int main(int argc, char *argv[])
{
  int sock;
  int flag=1;
  int len;
  int send_to;
  char *packet;
  char massage[100]="HELL in RAW SOCKET!";
  struct iphdr *ip_h = NULL;
  struct udphdr *udp_h = NULL;
  struct ether_header *eth_header = NULL;
  struct sockaddr_ll servaddr;
  unsigned char mac_my[6]={0xb8,0x27,0xeb,0x05,0x2a,0x7e}; //мой 
  unsigned char mac_ngty[6]={0x00,0x15,0x5D,0xDB,0xC7,0x66}; //нгту
 ///сейчас мак адрес моего пк
  

  packet = calloc(SIZE, sizeof(char));
  eth_header =(struct ether_header*) packet;
  ip_h = (struct iphdr*)(packet+sizeof(struct ether_header));
  udp_h = (struct udphdr*)(packet+sizeof(struct iphdr)+sizeof(struct ether_header));
  
  udp_h->source=htons(SOURCE_PORT);
  udp_h->dest=htons(DESTINATION_PORT);
  udp_h->check=0;
  udp_h->len=htons(sizeof(struct udphdr)+strlen(massage)+1);

  ip_h->ihl = 5;
  ip_h->version = 4;
  ip_h->tos = 0;
  ip_h->tot_len = htons((ip_h->ihl) + strlen(massage));
  ip_h->id = htons(11111);
  ip_h->frag_off = 0;
  ip_h->ttl=64;
  ip_h->protocol=IPPROTO_UDP; ///ну илил 17
  ip_h->saddr=inet_addr(SOURCE_IP);
  ip_h->daddr=inet_addr(DESTINATION_IP);
  ip_h->check=0;
  ip_h->check=csum((unsigned short*)ip_h, ip_h->ihl);
  
  eth_header->ether_type = htons(ETHERTYPE_IP);  //из библиотеки netinet/if_ether в define был ip протокол
  memcpy(eth_header->ether_shost,mac_my,6);  /// наш мак
  memcpy(eth_header->ether_dhost,mac_ngty,6);  /// мак приёмной стороны
  
  sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (sock == -1) 
  {
    perror("socket EROR ");
    exit(1);
  }
  memset(&servaddr, 0, sizeof(servaddr));
  servaddr.sll_family = AF_PACKET;
  servaddr.sll_ifindex = if_nametoindex(ETHER);
  servaddr.sll_halen = ETH_ALEN;
  memmove((void *) (servaddr.sll_addr), (void *) mac_ngty, ETH_ALEN);
  memmove(packet + sizeof(struct iphdr) + sizeof(struct udphdr)+sizeof(struct ether_header),massage,strlen(massage)+1 );
  
  len = sizeof(struct sockaddr_ll);

  send_to = sendto(sock, packet, SIZE, 0, (struct sockaddr *)&servaddr, len);
	if (send_to < 0) 
  {
    perror("EROR sendto");
  } 
  else
  {
    printf("Send to= %d\n", send_to);
  }
  close(sock);
   
}