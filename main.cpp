#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
//[리포트]
//pcap을 이용하여 송수신되는 packet의 다음 값을 출력하는 프로그램을 작성하라.
//eth.smac, eth.dmac / ip.sip, ip.dip / tcp.sport, tcp.dport / data(최대 16바이트까지)

//[학습]
//https://gitlab.com/…/ethernet-packet-disse…/pcap-programming

//ethernet / ip4 / tcp header format을 구글링을 통하여 숙지하고 wireshark를 통하여 실습해 보면서 이해할 것. 각각 헤더의 모든 필드를 다 암기할 필요는 없고, 각 header의 format을 보고 본 과제와 관련된 mac, ip, port 위치 정도를 알아 내는 것이 본 과제의 목표임.

//#define ETHERTYPE_IP 0x800;
#define ETHERTYPE_ARP 0x0806;
#define IPPROTO_TCP 0x6;
#define IPPROTO_UDP 0x11;
#define IPPROTO_ICMP 0x1;




typedef struct _EthHead{
                              //#include <st0dint>
  u_char eth_dmac[6]; // 8bit = uint8_t 16bit = uint16_t 32bit = uint32_t 
  u_char eth_smac[6];
  uint16_t type;  // u_short? // u_char나 u_short 같은 거 가급적 쓰지 말기 
  } EthHead;


typedef struct _IpHead{
  u_char  ip_eth[sizeof(EthHead)-1];
  u_char  ip_ver : 4;
  u_short ip_hLength : 4;
  u_char  ip_DiffServiceCOP : 6;
  u_char  ECN : 2;
  uint16_t  ip_tLength;
  uint16_t  ip_id;
  u_char  ip_reservedBit : 1;
  u_char  ip_dontFragment : 1;
  u_char  ip_MoreFragment : 1;
  u_short  ip_FragmentOffset1 : 7;
  u_short  ip_FragmentOffset2 : 6;
  u_char  ip_TTL;
  u_char  ip_protocol; //tcp or udp 
  uint16_t  ip_checksum;
  u_char  ip_sIP[4];
  u_char  ip_dIP[4];  
} IpHead;

typedef struct _TcpHead{
//  u_char tct_ip[sizeof(IpHead)-1];
  uint16_t tcp_sPort;
  uint16_t tcp_dPort;
  uint32_t tcp_seq;
  uint32_t tcp_ack;
  u_char tcp_Reserved : 3;
  u_char tcp_Nonce : 1;
  u_char tcp_CWR : 1;
  u_char tcp_ECN_Echo : 1;
  u_char tcp_Urgent : 1;
  u_char tcp_Acknowlegement : 1;
  u_char tcp_Push : 1;
  u_char tcp_Reset : 1;
  u_char tcp_Syn : 1;
  u_char tcp_Fin : 1;
  uint16_t tcp_window;
  uint16_t tcp_checksum;
  uint16_t tcp_urgentP;
} TcpHead; 

  //ntohs?


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {

  char track[] = "포렌식"; // "취약점", "컨설팅", "포렌식"
  char name[] = "김영웅";
  printf("[bob7][%s]pcap_test[%s]\n", track, name);

  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];// The device that we intend to sniff
  char errbuf[PCAP_ERRBUF_SIZE]; // error string
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);//session handle, start of sniffing
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);//no session
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;         // The header that pcap gives us
    const u_char* packet;               // The actual packet
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;

    //printf("%u bytes captured\n", header->caplen);
    
    EthHead* Eth1;
    Eth1 = (EthHead*)malloc(sizeof(EthHead));
    memcpy(Eth1, (EthHead*)packet, sizeof(EthHead));
    printf("===============================\n");
    printf("eth_smac    :       ");
    for(int i=0; i<6; i++){
      if (i==5){
        printf("%02x\n", Eth1->eth_smac[i]);
      }        
      else{
        printf("%02x:", Eth1->eth_smac[i]);
      }
    }    
    printf("eth_dmac    :       ");
    for(int i=0; i<6; i++){
      if (i==5){
        printf("%02x\n", Eth1->eth_dmac[i]);
      }
      else{
        printf("%02x:", Eth1->eth_dmac[i]);
      }
    }
  

    if(ntohs(Eth1->type) == 0x800){
      IpHead* IP1;
      IP1 = (IpHead*)malloc(sizeof(IpHead));
      memcpy(IP1, (IpHead*)packet, sizeof(IpHead));

      printf("ip.sIP      :       ");
      for(int i=0; i<4; i++){
        if (i==3){
          printf("%d\n", IP1->ip_sIP[i]);
        }
        else{
          printf("%d.", IP1->ip_sIP[i]);
        }
      }

      printf("ip.dIP      :       ");
      for(int i=0; i<4; i++){
        if (i==3){
          printf("%d\n", IP1->ip_dIP[i]);
        }
        else{
          printf("%d.", IP1->ip_dIP[i]);
        }

      }

    if(ntohs(IP1->ip_protocol)==0x600){
      TcpHead* Tcp1;
      Tcp1 = (TcpHead*)malloc(sizeof(TcpHead));
      memcpy(Tcp1, (TcpHead*)packet, sizeof(TcpHead));

      printf("Tcp.sport   :       ");
      printf("%d\n", Tcp1->tcp_sPort);
      
      printf("Tcp.dport   :       ");
      printf("%d\n", Tcp1->tcp_dPort);
    
      free(Tcp1);

    }

    free(IP1);

      }
    free(Eth1);

    }
  printf("===============================\n");

  }
    