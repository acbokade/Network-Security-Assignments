#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

using namespace std;
const int backLog = 3;
const int maxDataSize = 1460;

main()
{

uint16_t serverPort=3002;
string serverIpAddr = "127.0.0.1";
cout<<"Enter the ip address and port number to communicate with"<<endl;
cin>>serverIpAddr;
cin>>serverPort;

int clientSocketFd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
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
serverSockAddressInfo.sin_port = htons(serverPort);
//serverSockAddressInfo.sin_addr.s_addr = INADDR_ANY;
inet_pton(AF_INET, serverIpAddr.c_str(), &(serverSockAddressInfo.sin_addr));

memset(&(serverSockAddressInfo.sin_zero), '\0', 8);


socklen_t sinSize = sizeof(struct sockaddr_in);
int flags = 0;
int dataRecvd = 0, dataSent = 0;
struct sockaddr_in clientAddressInfo;
char rcvDataBuf[maxDataSize], sendDataBuf[maxDataSize];
string sendDataStr, rcvDataStr;

 cin.ignore();
while(1)
{
   cout<<"Enter data to send"<<endl;

   memset(&sendDataBuf, 0, maxDataSize);
//   cin.ignore();
   cin.clear();
   //cin.getline(sendDataBuf,maxDataSize);
   getline(cin, sendDataStr);
   cout<<sendDataStr.c_str();
   
   //getline(cin,sendDataStr);
   dataSent = sendto(clientSocketFd, sendDataStr.c_str(), sendDataStr.length(), flags, (struct sockaddr *)&serverSockAddressInfo, sinSize);
  // cout<<"Is data sent successfully"<<dataSent<<endl;
   if(!strcmp(sendDataStr.c_str(), "bye"))
   {
      break;
   }


   memset(&rcvDataBuf, 0, maxDataSize);
   dataRecvd = recvfrom(clientSocketFd, &rcvDataBuf, maxDataSize, flags, (struct sockaddr *)&serverSockAddressInfo, &sinSize);
   rcvDataStr = rcvDataBuf;
   cout<<rcvDataStr.c_str()<<endl;
   if(!strcmp(rcvDataStr.c_str(), "bye"))
   {
      break;
   }

}

cout<<"All done closing socket now"<<endl;
close(clientSocketFd);


}
