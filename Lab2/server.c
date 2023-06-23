#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "header.h"

int main(int argc , char *argv[]){

    //Create TCP socket//
    int sockfd, port=45525, newsockfd, n;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    char buff[256];
    char* greet = "Hi, I'm server 108021132";
    
    //Set up server's address.//
    struct sockaddr_in serv_addr, cli_addr;
    int addrlen = sizeof(serv_addr);
    socklen_t clilen;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    serv_addr.sin_addr.s_addr = INADDR_ANY;

    //Bind socket to the address.//  
    bind(sockfd,(struct sockaddr*)&serv_addr,sizeof(serv_addr));


    //Listening the socket.//
    listen(sockfd,5);


    //Accept the connect request.//
    clilen = sizeof(cli_addr);
    newsockfd = accept(sockfd,(struct sockaddr*)&serv_addr, (socklen_t*)&addrlen);


    //Send message to client.//
    send(
        newsockfd,
        greet,
        strlen(greet),
        0
    );
    


    ////////////////////////////////////////////////////////////
    //                   TASK 1(Server)                       //
    ////////////////////////////////////////////////////////////
    // TODO: Create a TCP socket bind to port 45525.          //
    // TODO: Listen the TCP socket.                           //
    // TODO: Accept the connect and get the Client socket     //
    //       file descriptor.                                 //
    // TODO: Send 1 message "Hi, I'm server {Your_student_ID}"//
    //       to client.                                       //
    // Then go finish the client.c TASK 1                     //
    ////////////////////////////////////////////////////////////

    ////////////////////////////////////////////////////////////
    //                   TASK 2,3(Server)                     //
    ////////////////////////////////////////////////////////////
    // TODO: Pass the client socket fd into serverfuntion()   //
    //                                                        //
    // Example:                                               //
    //           serverfunction(client_fd);                   //
    //                                                        //
    // Then go finish the client.c TASK2,3                    //
    ////////////////////////////////////////////////////////////
    serverfunction(newsockfd);

}
