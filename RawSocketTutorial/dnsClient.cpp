#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "print.h"

using namespace std;
const int backLog = 3;
const int maxDataSize = 1460;

// example convert rawsocket.tut ---> 9rawsocket3tut
void convertNameToDNSFormat(unsigned char* query_name, unsigned char* name) 
{
    // appending dot at the last of name so that we can
    // process text before dot 
    strcat((char*)name,".");
    int l = strlen((char*)name);
    int prev_dot_idx = 0;

    for(int i=0;i<l;i++) {
        if(name[i] == '.') {
            // number of characters = i - prev_dot_idx
            int n_chars = i - prev_dot_idx;
            *query_name = n_chars;
            query_name++;
            for(int j=prev_dot_idx; j<i;j++) {
                *query_name = name[j];
                query_name++;
            }
            prev_dot_idx = i+1;
        }
    }
    // appending null character at the end to denote end of string
    *query_name = '\0';
    query_name++;
}

main()
{

    uint16_t serverPort = 53;
    string serverIpAddr = "127.0.0.1";
    cout<<"Enter the ip address and port number to communicate with"<<endl;
    cin>>serverIpAddr;
    cin>>serverPort;

    int clientSocketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    unsigned char buffer[65536];
    unsigned char *query_name, *reader;

    struct dnshdr* dns = NULL;

    if(!clientSocketFd)
    {
        cout<<"Error creating socket"<<endl;
        exit(1);
    }

    string clientIpAddr = "192.168.1.21";
    struct sockaddr_in clientSockAddressInfo;
    clientSockAddressInfo.sin_family = AF_INET;
    clientSockAddressInfo.sin_port = htons(4000);
    //serverSockAddressInfo.sin_addr.s_addr = INADDR_ANY;
    inet_pton(AF_INET, clientIpAddr.c_str(), &(clientSockAddressInfo.sin_addr));

    memset(&(clientSockAddressInfo.sin_zero), '\0', 8);

    int ret = bind(clientSocketFd, (struct sockaddr *)&clientSockAddressInfo, sizeof(struct sockaddr));
    if(ret<0)
    {  
        cout<<"Error binding socket"<<endl;
        close(clientSocketFd);
        exit(1);
    }

    struct sockaddr_in serverSockAddressInfo;
    serverSockAddressInfo.sin_family = AF_INET;
    serverSockAddressInfo.sin_port = htons(53); // port 53
    //serverSockAddressInfo.sin_addr.s_addr = INADDR_ANY;
    inet_pton(AF_INET, serverIpAddr.c_str(), &(serverSockAddressInfo.sin_addr));

    memset(&(serverSockAddressInfo.sin_zero), '\0', 8);

    dns = (struct dnshdr*) &buffer;

    // reference for filling fields
    // unsigned short id; // 16-bit identifcation number sometimes called transaction id
    // unsigned char rd: 1; // recursion is enabled or not
    // unsigned char tc: 1; // truncated message or not
    // unsigned char aa: 1; // authorative response or not
    // unsigned char opcode: 4; // purpose of message 
    // unsigned char qr: 1; // flag for query or response

    // unsigned char rcode: 4; // response code 
    // unsigned char cd: 1; // checking disabled or not
    // unsigned char ad: 1; // authenticated data or not
    // unsigned char z: 1; 
    // unsigned char ra: 1; // recrusion available or not
    // unsigned short n_q; // number of question entries
    // unsigned short n_a; // number of answer entries
    // unsigned short n_auth; // number of authority entries
    // unsigned short n_add; // number of additional (resource) entries

    dns->id = (unsigned short) htons(getpid());
    dns->rd = 0;
    dns->tc = 0;
    dns->aa = 0;
    dns->opcode = 0;
    dns->qr = 0;  // since it is a query
    dns->rcode = 0;
    dns->cd = 0;
    dns->ad = 0;
    dns->z = 0;
    dns->ra = 0;
    dns->n_q = htons(1);  // single query
    dns->n_a = 0;
    dns->n_auth = 0;
    dns->n_add = 0;

    // skipping query_name at the end of dns header
    query_name = (unsigned char*)&buffer[sizeof(struct dnshdr)];

    // dns query name
    unsigned char _name[] = "rawsocket.tut";
    unsigned char* name = _name;
    convertNameToDNSFormat(query_name, name);

    int dns_header_size = sizeof(struct dnshdr);
    int query_name_size = strlen((const char*)query_name);

    // skipping question to end of query_name 
    struct dns_question* question = (struct dns_question*)&buffer[dns_header_size + query_name_size + 1];

    question->type = htons(1);  // type A
    question->_class = htons(1);

    socklen_t sinSize = sizeof(struct sockaddr_in);
    int flags = 0;
    int dataRecvd = 0, dataSent = 0;
    char rcvDataBuf[maxDataSize], sendDataBuf[maxDataSize];
    string sendDataStr, rcvDataStr;

    int dns_question_size = sizeof(dns_question);

    //send the dns query
    int query_size = dns_header_size + query_name_size + dns_question_size;
    dataSent = sendto(clientSocketFd, (char*) buffer, query_size, flags, (struct sockaddr*)&serverSockAddressInfo, sinSize);

    if(dataSent < 0) {
        printf("sending dns query failed\n");
    }
    printf("Sending DNS query succeeded\n");
    
    // cin.ignore();
    // while(1)
    // {
    //     cout<<"Enter data to send"<<endl;

    //     memset(&sendDataBuf, 0, maxDataSize);
    //     //   cin.ignore();
    //     cin.clear();
    //     //cin.getline(sendDataBuf,maxDataSize);
    //     getline(cin, sendDataStr);
    //     cout<<sendDataStr.c_str();
        
    //     //getline(cin,sendDataStr);
    //     dataSent = sendto(clientSocketFd, sendDataStr.c_str(), sendDataStr.length(), flags, (struct sockaddr *)&serverSockAddressInfo, sinSize);
    //     // cout<<"Is data sent successfully"<<dataSent<<endl;
    //     if(!strcmp(sendDataStr.c_str(), "bye"))
    //     {
    //         break;
    //     }


    //     memset(&rcvDataBuf, 0, maxDataSize);
    //     dataRecvd = recvfrom(clientSocketFd, &rcvDataBuf, maxDataSize, flags, (struct sockaddr *)&serverSockAddressInfo, &sinSize);
    //     rcvDataStr = rcvDataBuf;
    //     cout<<rcvDataStr.c_str()<<endl;
    //     if(!strcmp(rcvDataStr.c_str(), "bye"))
    //     {
    //         break;
    //     }

    // }
    cout<<"All done closing socket now"<<endl;
    close(clientSocketFd);
}
