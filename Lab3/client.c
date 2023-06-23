#include "header.h"

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
char* get_fix_part(char flag)
{
    char* fix = malloc(2);
    fix[0] = 0x50;
    if(flag == 'a')
    {
        fix[1] = ACK;
    }
    else if(flag == 's')
    {
        fix[1] = SYN;
    }
    return fix;
}
void show_header(Segment*s)
{
    for(int i=0;i<20;i++)
    {
        printf("%x ",s->header[i]);
    }
    printf("\n");
}
void fill_header(Segment* s, char* data, int len, int index)
{
    for(int i=0;i<len;i++)
    {
        s->header[index+i] = data[i];
    }
}
void create_header(Segment* s,char flag)
{
    memset(s->pseudoheader,0,12);
    char ip[] = "127.0.0.1";
    strcat(s->pseudoheader,IP_to_hex(ip));
    strcat(s->pseudoheader,IP_to_hex(ip));
    //strcat(s->pseudoheader,num_to_hex(s->l3info.protocol,2));
    //strcat(s->pseudoheader,num_to_hex(s->l4info.HeaderLen,2));
    char* prot = num_to_hex(6,2);
    s->pseudoheader[8] = prot[0];
    s->pseudoheader[9] = prot[1];
    char* head_len = num_to_hex(20,2);
    s->pseudoheader[10] = head_len[0];
    s->pseudoheader[11] = head_len[1];
    // TCP header
    memset(s->header,0,20);
    // printf("sp:%d\n",s->l4info.SourcePort);
    // show_header(s);
    fill_header(s,num_to_hex(s->l4info.SourcePort,2),2,0);
    // show_header(s);
    fill_header(s,num_to_hex(s->l4info.DesPort,2),2,2);
    // show_header(s);
    fill_header(s,num_to_hex(s->l4info.SeqNum,4),4,4);
    // show_header(s);
    fill_header(s,num_to_hex(s->l4info.AckNum,4),4,8);
    // show_header(s);
    fill_header(s,get_fix_part(flag),2,12);
    // show_header(s);
    fill_header(s,num_to_hex(s->l4info.WindowSize,2),2,14);
    
    // show_header(s);
}
int recv_packets(int sockfd,struct Segment* s)
{
    char buff[1020];
    int total_size = recv(sockfd,buff,sizeof(buff),0);
    s->l4info.SourcePort = (uint32_t) ((0xff & buff[0])<<8) + (0xff & buff[1]);
    s->l4info.DesPort = (uint32_t) ((0xff & buff[2])<<8) + (0xff & buff[3]);
    s->l4info.SeqNum = (uint32_t)(((0xff & buff[4])<<24) + ((0xff & buff[5])<<16) + ((0xff & buff[6])<<8) + (0xff & buff[7]));
    s->l4info.AckNum = (uint32_t)(((0xff & buff[8])<<24) + ((0xff & buff[9])<<16) + ((0xff & buff[10])<<8) + (0xff & buff[11]));
    s->l4info.CheckSum = (uint32_t)(((0xff & buff[16])<<8) + (0xff & buff[17]));
    s->p_len = total_size - 20;
    memcpy(s->header, buff, 20);
    memcpy(s->payload, buff+20, s->p_len);
    memset(s->pseudoheader,0,12);
    s->pseudoheader[0] = 127;
    s->pseudoheader[1] = 0;
    s->pseudoheader[2] = 0; 
    s->pseudoheader[3] = 1;
    s->pseudoheader[4] = 127;
    s->pseudoheader[5] = 0;
    s->pseudoheader[6] = 0;
    s->pseudoheader[7] = 1;
    s->pseudoheader[8] = 0;
    s->pseudoheader[9] = 6;
    s->pseudoheader[10] = 0;
    s->pseudoheader[11] = 20;
    return total_size;
}   
int check_packet(struct Segment* s)
{
    char tmp[1032];
    memcpy(tmp,s->header,sizeof(s->header));
    memcpy(tmp+20,s->pseudoheader,sizeof(s->pseudoheader));
    memcpy(tmp+32,s->payload,sizeof(char)*s->p_len);
    //empty checksum field for header
    tmp[16] = 0x00;
    tmp[17] = 0x00;
    uint16_t mycheck = mychecksum(tmp,32+s->p_len);
    // retransmission is needed if not equal 
    printf("mycheck:%u check: %u\n",mycheck, s->l4info.CheckSum);
    return mycheck != (uint16_t)s->l4info.CheckSum;
}
void send_packet(struct Segment* s,int retrans,int sockfd)
{
    struct Segment tran;
    tran.l4info.SourcePort = s->l4info.DesPort;
    tran.l4info.DesPort = s->l4info.SourcePort;
    tran.l4info.SeqNum = s->l4info.AckNum;
    if(retrans)
    {
        tran.l4info.AckNum = s->l4info.SeqNum;
    }
    else
    {
        tran.l4info.AckNum = s->l4info.SeqNum + s->p_len;
    }
    create_header(&tran,'a');
    send(sockfd,tran.header,20,0);
}
int main(){
    /*---------------------------UDT SERVER----------------------------------*/
    srand(getpid());
        //Create socket.
    int socket_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        printf("Create socket fail!\n");
        return -1;
    }

    //Set up server's address.
    struct sockaddr_in serverAddr = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = inet_addr("127.0.0.1"),
        .sin_port = htons(45525)
    };
    int server_len = sizeof(serverAddr);
    //Connect to server's socket.
    if (connect(socket_fd, (struct sockaddr *)&serverAddr, server_len) == -1) {
        printf("Connect server failed!\n");
        close(socket_fd);
        exit(0);
    }
    /*---------------------------UDT SERVER-----------------------------------*/
    
    

    /*---------------------------3 way hand shake-----------------------------*/
    /*                                                                        */                                              
    /* TODO: Make a three way handshake with RDT server by using TCP header   */
    /*       char header[20] (lab2).                                          */
    /*       Make sure the SrcPort(Random), DesPort(45525), Seg#, Ack#, FLAG  */
    /*       are correct.                                                     */
    /*                                                                        */                                              
    /*---------------------------3 way hand shake-----------------------------*/
    
    struct Segment syn;
    syn.l4info.SourcePort = rand() % 65536;
    syn.l4info.DesPort = SERVER_PORT;
    syn.l4info.SeqNum = 0;
    syn.l4info.AckNum = 0;
    syn.l4info.Flag = SYN;
    create_header(&syn,'s');
    send(socket_fd, syn.header, 20, 0);

    // receive SYN-ACK
    struct Segment syn_ack;
    recv(socket_fd, &syn_ack.header, 20, 0);
    // printf("rec from server: ");
    // show_header(&syn_ack);
    struct Segment ack;
    ack.l4info.SourcePort = syn.l4info.SourcePort; // Same source port
    ack.l4info.DesPort = syn.l4info.DesPort; // Same destination port
    ack.l4info.SeqNum = (uint32_t)(((0xff & syn_ack.header[8])<<24) + ((0xff & syn_ack.header[9])<<16) + ((0xff & syn_ack.header[10])<<8) + 0xff & syn_ack.header[11]); // Next sequence number
    ack.l4info.AckNum = (uint32_t)(((0xff & syn_ack.header[4])<<24) + ((0xff & syn_ack.header[5])<<16) + ((0xff & syn_ack.header[6])<<8) + (0xff & syn_ack.header[7]) + 1); // Acknowledgment number from SYN-ACK packet
    ack.l4info.Flag = ACK;
    create_header(&ack,'a');
    send(socket_fd, ack.header, 20, 0);

    /*----------------------------receive data--------------------------------*/
    /*                                                                        */                                              
    /* TODO: Receive data from the RDT server.                                */
    /*       Each packet will be 20bytes TCP header + 1000bytes paylaod       */
    /*       exclude the last one. (the payload may not be exactly 1000bytes) */
    /*                                                                        */
    /* TODO: Once you receive the packets, you should check whether it's      */                                                            
    /*       corrupt or not (checksum) , and send the corresponding ack       */                                                  
    /*       packet (also a char[20] ) back to the server.                    */
    /*                                                                        */
    /* TODO: fwrite the payload into a .jpg file, and check the picture.      */
    /*                                                                        */                                              
    /*----------------------------receive data--------------------------------*/
    FILE* new_file = fopen("new_image.jpg", "wb");
    struct Segment current_packet;
    struct Segment last_packet = current_packet;
    int wait_for_retrans = 0;
    int last = 0;
    while (!last) {
        int recv_size = recv_packets(socket_fd,&current_packet);
        int corrupted = check_packet(&current_packet);
        if(corrupted)
        {
            printf("corrupt!! seq: %d\n",current_packet.l4info.SeqNum);
            if(!wait_for_retrans)
            {
                last_packet = current_packet;
            }
            wait_for_retrans = 1;
        }
        if(!corrupted && wait_for_retrans && (last_packet.l4info.SeqNum == current_packet.l4info.SeqNum))
        {
            // Write payload to file
            wait_for_retrans = 0;
            fwrite(current_packet.payload, 1, current_packet.p_len, new_file);
            last_packet = current_packet;
            send_packet(&current_packet,0,socket_fd);
            printf("fix corrupt write. Seq: %d\n",current_packet.l4info.SeqNum);
            if(current_packet.p_len < 1000){last = 1;}
            continue;
        }
        else if(!wait_for_retrans && !corrupted)
        {
            fwrite(current_packet.payload, 1, current_packet.p_len, new_file);
            last_packet = current_packet;
            printf("no corrupt write. Seq: %d\n", current_packet.l4info.SeqNum);
            send_packet(&current_packet,0,socket_fd);
            if(current_packet.p_len < 1000){last = 1;}
            continue;
        }
        else
        {
            send_packet(&last_packet,1,socket_fd);
            printf("wait for Ack: %d\n", last_packet.l4info.AckNum);
        }
        
        
    }

    fclose(new_file);
    /*-------------------------Something important----------------------------*/
    /* NOTE: TO make lab3 simple                                              */
    /*                                                                        */                                              
    /*       1. The SrcIP and DesIP are both 127.0.0.1,                       */
    /*          Tcp header length will be 20byts, windowsize = 65535 bytes    */                                              
    /*       2. The Handshake packets won't be corrupt.                       */
    /*       3. The packet will only corrupt but not miss or be disordered.   */                                              
    /*       4. Only the packets come from server may corrupt.(don't have to  */
    /*          worry that the ack sent by client will corrupt.)              */
    /*       5. We offer mychecksum() for you to verify the checksum, and     */
    /*          don't forget to verify pseudoheader part.                     */
    /*       6. Once server finish transmit the file, it will close the       */
    /*          client socket.                                                */                                              
    /*       7. You can adjust server by                                      */                                              
    /*          ./server {timeout duration} {corrupt probability}             */                                              
    /*                                                                        */                                              
    /*-------------------------Something important----------------------------*/

}
