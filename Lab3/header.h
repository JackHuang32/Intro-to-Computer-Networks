#pragma once
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#define SERVER_PORT 45525
#define SYN 0X2
#define ACK 0X10 
#define SYNACK 0X12 
#define ACKPSH 0X18

typedef struct l4info{
    uint32_t SourcePort,DesPort,SeqNum,AckNum,HeaderLen,Flag,WindowSize,CheckSum;
}L4info;
typedef struct l3info{
    char SourceIpv4[16], DesIpv4[16];
    uint32_t protocol;
}L3info;
typedef struct Segment{
    char header[20];
    char pseudoheader[12];
    char payload[1000];
    int p_len;
    L3info l3info;
    L4info l4info;
}Segment;
uint16_t mychecksum(char* buffer, int packet_len);
uint16_t mychecksum(char* buffer, int buffer_len){
    if((buffer_len)%2==1) buffer_len++;
    uint32_t checksum = 0;
    uint16_t* p = (uint16_t*)buffer;
    for(int i =0;i<(buffer_len/2);i++){    
        checksum += (*(p+i)); 
        while(checksum>0xffff){
            checksum = (checksum&0xffff) + (checksum>>16);
            
        }
    }
    
    checksum = (~(checksum))&0xffff;
    return (uint16_t)ntohs(checksum);
}
