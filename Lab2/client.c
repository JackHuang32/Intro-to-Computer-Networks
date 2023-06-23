#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "header.h"
void swap(char* a,char* b)
{
    char tmp = *a;
    *a = *b;
    *b = tmp;
}
void reverse(char* str)
{
    // l for swap with index 2
    int l = 0;
    int r = strlen(str) - 2;
 
    // swap with in two-2 pair
    while (l < r) {
        swap(&str[l++], &str[r++]);
        swap(&str[l++], &str[r]);
        r = r - 3;
    }
}
char* IP_to_hex(char* ip)
{
    char ip_addr[100];
    sprintf(ip_addr,"%08x",inet_addr(ip));
    reverse(ip_addr);
    char* addr = malloc(5);
    for(int i=0;i<4;i++)
    {
        char tmp[3]={0};
        strncpy(tmp,ip_addr+i*2,2);
        addr[i] = (strtol(tmp,NULL,16)&0xff);
    }
    return addr;
}
char* num_to_hex(uint32_t n,int bytes)
{
    if(bytes  == 2)
    {
        char* num = malloc(3*sizeof(char));
        num[0] = n >> 8;
        num[1] = n & 0xff;
        return num;
    }
    if(bytes  == 4)
    {
        char* num = malloc(5*sizeof(char));
        num[0] = n >> 24 & 0xff;
        num[1] = n >> 16 & 0xff;
        num[2] = n >> 8 & 0xff;
        num[3] = n & 0xff;
        return num;
    }
    return (char*)malloc(1);
}
uint32_t get_tcp_header_sum(Segment s)
{
    uint32_t header_sum = 0;
    for(int i=0;i<8;i++)
    {
        uint32_t tmp = ((s.header[2*i]<<8) & 0xffff) + (s.header[2*i+1]&0xff);
        header_sum += tmp;
    }
    return header_sum;
}
void fill_checksum(Segment* s)
{
    uint32_t source_ip = ((s->pseudoheader[0]<<8)& 0xffff) + 
                        (s->pseudoheader[1]&0xff) + 
                        ((s->pseudoheader[2]<<8)& 0xffff) + 
                        (s->pseudoheader[3]&0xff);

    uint32_t des_ip = ((s->pseudoheader[4]<<8)& 0xffff) +
                    (s->pseudoheader[5]&0xff) +
                    ((s->pseudoheader[6]<<8)& 0xffff) +
                    (s->pseudoheader[7]&0xff);

    uint32_t protocol = ((s->pseudoheader[8]<<8)& 0xffff)+
                        (s->pseudoheader[9]&0xff);

    uint32_t header_len = ((s->pseudoheader[10]<<8)& 0xffff) + 
                          (s->pseudoheader[11]& 0xff);
    //printf("pseudo 1~4: %x %x %x %x\n",s->pseudoheader[0],s->pseudoheader[1],s->pseudoheader[2],s->pseudoheader[3]);
    // printf("%x %x %x %x\n",source_ip,des_ip,protocol,header_len);
    uint32_t pseudo_header = source_ip+des_ip+protocol+header_len;
    uint32_t tcp_header = get_tcp_header_sum(*s);
    uint32_t carry = (pseudo_header+tcp_header)>>16;
    uint32_t end_around = ((pseudo_header+tcp_header) & 0xffff) + carry;
    uint32_t checksum = ~end_around & 0xffff;
    s->header[16] = checksum>>8;
    s->header[17] = checksum & 0xff;
    
    return;
}
char* get_fix_part()
{
    char* fix = malloc(2);
    fix[0] = 0x50;
    fix[1] = 0x10;
    return fix;
}
void show_pseudo(Segment*s)
{
    for(int i=0;i<12;i++)
    {
        printf("%x ",s->pseudoheader[i]);
    }
    printf("\n");
}
void create_header(Segment* s)
{
    // pseudo header
    strcat(s->pseudoheader,IP_to_hex(s->l3info.SourceIpv4));
    strcat(s->pseudoheader,IP_to_hex(s->l3info.DesIpv4));
    //strcat(s->pseudoheader,num_to_hex(s->l3info.protocol,2));
    //strcat(s->pseudoheader,num_to_hex(s->l4info.HeaderLen,2));
    char* prot = num_to_hex(s->l3info.protocol,2);
    s->pseudoheader[8] = prot[0];
    s->pseudoheader[9] = prot[1];
    char* head_len = num_to_hex(s->l4info.HeaderLen*4,2);
    s->pseudoheader[10] = head_len[0];
    s->pseudoheader[11] = head_len[1];
    // show_pseudo(s);
    // TCP header
    strcat(s->header,num_to_hex(s->l4info.SourcePort,2));
    strcat(s->header,num_to_hex(s->l4info.DesPort,2));
    strcat(s->header,num_to_hex(s->l4info.SeqNum,4));
    strcat(s->header,num_to_hex(s->l4info.AckNum,4));
    strcat(s->header,get_fix_part());
    strcat(s->header,num_to_hex(s->l4info.WindowSize,2));
    fill_checksum(s);
}
int main(int argc , char *argv[])
{   
    char buff[256]={0};
    //Create TCP socket.//
    int client_fd, port=45525;
    client_fd = socket(AF_INET,SOCK_STREAM,0);

    //Set up server's address.//
    struct sockaddr_in serv_addr, cli_addr;
    int addrlen = sizeof(serv_addr);
    socklen_t clilen;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    //Connect to server's socket.//
    connect(client_fd,(struct sockaddr*)&serv_addr,sizeof(serv_addr));
    
    //Receive message from server and print it out.//
    recv(
        client_fd,
        buff,
        sizeof(buff),
        0
    );
    //printf("Done recieving!\n");
    printf("From server: %s\n",buff);


    //////////////////////////////////////////////////////////
    //                   TASK1(Client)                      //  
    //////////////////////////////////////////////////////////
    // TODO: create a socket and connet to server.          //
    //       (server's IP address = "127.0.0.1")            //
    //       (server's Port number = 45525)                 //
    //                                                      //
    // TODO: Receive 1 message from server and print it out.//
    //       (The message you sent from server)             //
    //////////////////////////////////////////////////////////
    


    ///////////////////////////////////////////////////////////
    //                   TASK2,3(Client)                     //
    ///////////////////////////////////////////////////////////
    // TODO: Instantiate a Segment                           //
    // TODO: Pass your socket_fd and the instance of Segment //
    //       into the receivedata().                         //
    // TODO: Write your own function to create header.       //
    //       (All information is in the Segment instance.    //
    // TODO: Use sendheader(char* header) to send the header //
    //       to server.                                      //
    //                                                       //
    // Example:                                              //
    //                                                       //
    //       Segment s;                                      //
    //       receivedata(sock_fd,&s);                        //
    //       myheadercreater(&s);  //your own function       //
    //       sendheader(sock_fd,s.header);                   // 
    //                                                       //
    //                                                       //
    // Then you will see the result.                         //  
    ///////////////////////////////////////////////////////////
    

    Segment s;
    receivedata(client_fd,&s);
    create_header(&s);
    // memset(s.header,0x12,sizeof(s.header));

    sendheader(client_fd,s.header);
    
    close(client_fd);
}