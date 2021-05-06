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
string err_msg = "Pass <-s> argument for server and <-c host_name> argument for client";

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
	// declaring sock address
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

	// listening for max 1 client connection
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
	cout<<"Connected to host_name ...\n";

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
	char reply[BUF_SIZE]; // reply message that is sent from user to peer
	char response[BUF_SIZE]; // response message from peer to user

	char* host_name; // host name of server

	if(argc == 1) {
		cout<<err_msg<<endl;
		return 1;
	} else {
		if(argc == 2) {
			if(string(argv[1]) == "-s") {
				is_server = true;
			} else {
				cout<<err_msg<<endl;
				return 1;
			}
		} else if(argc == 3) {
			if(string(argv[1]) == "-c") {
				is_server = false;
				host_name = argv[2];
				cout<<"Host name is "<<host_name<<endl;
			} else {
				cout<<err_msg<<endl;
				return 1;
			}
		} else {
			cout<<err_msg<<endl;
			return 1;
		}
	}

	int sock;	// socket fd
	
	// initializing openssl ciphers, algos, digests, etc
	init_openssl();
	
	int n, bytes_read;

	// declaring ssl object
	SSL* ssl;

	// declaring ssl context object
	SSL_CTX* ctx;

	if(is_server) {
		// ***************** SERVER (BOB) ***********************
		// creating socket
		sock = create_server_socket(SERVER_LISTEN_PORT);

		// declaring addres for client
		struct sockaddr_in client_addr;
		uint len = sizeof(client_addr);	

		// accepting client connection
		int client = accept(sock, (struct sockaddr*)&client_addr, &len);
		if(client < 0) {
				perror("Unable to accept");
				exit(EXIT_FAILURE);
		}
		char ip_str[INET_ADDRSTRLEN];
		inet_ntop(AF_INET, &(client_addr.sin_addr), ip_str, INET_ADDRSTRLEN);
		printf("Connected to client with IP %s\n", ip_str);

		// server receives "chat_hello"
		bzero(response, BUF_SIZE);
		bytes_read = read(client, response, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from client:\n"<<response;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// server sends "chat_reply"
		bzero(reply, BUF_SIZE);
		n = 0;
		cout<<"Write your message:\n";
		while((reply[n++] = getchar()) != '\n');
		write(client, reply, BUF_SIZE);

		// server receives "chat_STARTTLS"
		bzero(response, BUF_SIZE);
		bytes_read = read(client, response, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from client:\n"<<response;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// server sends "chat_STARTTLS_ACK"
		bzero(reply, BUF_SIZE);
		n = 0;
		cout<<"Write your message:\n";
		while((reply[n++] = getchar()) != '\n');
		write(client, reply, BUF_SIZE);

		// creating ssl context 
		ctx = create_context();
		cout<<"SSL context created...\n";
		// configuring ssl context by loading certs, keys,..
		configure_context(ctx);
		cout<<"Context configured...\n";

		// creating ssl object with given context
		ssl = SSL_new(ctx);

		// setting the file descriptor of client socket with ssl
		SSL_set_fd(ssl, client);

		// server accepts client connection
		if(SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
			// displaying peer certificates
			cout<<"Displaying peer certificates...\n";
			display_certificates(ssl);

			// returns the result of the verification of the X509 certificate presented by the peer
			if(SSL_get_verify_result(ssl) == X509_V_OK) {
			    cout<<"Certificate verification passed\n";
			} else {
				cout<<"Certificate verification failed\n";
			}

			// printing SSL version used in connection
			cout<<"SSL version used: ";
			cout<<SSL_get_version(ssl)<<endl;

			while(true) {
				// server receives message from client
				bzero(response, BUF_SIZE);
				bytes_read = SSL_read(ssl, response, BUF_SIZE);
				cout<<"Received from client:\n";
				if(bytes_read > 0) {
					cout<<response;
				} else {
					ERR_print_errors_fp(stderr);
				}
				// terminate connection if client sends chat_close
				if(!strcmp(response, "chat_close\n")) break;

				// server sends message to client
				bzero(reply, BUF_SIZE);
				n = 0;
				cout<<"Write your message:\n";
				while((reply[n++] = getchar()) != '\n');
				SSL_write(ssl, reply, strlen(reply));
				// terminate connection if server sends chat_close
				if(!strcmp(reply, "chat_close\n")) break;
			}
		}
		// close the socket associated with client socket
		close(client);
		// close the socket associated for listening
		close(sock);
	} else {
		// ***************** CLIENT (ALICE) ***********************
		// creating socket
		sock = create_client_socket(host_name, SERVER_LISTEN_PORT);

		// client sends "chat_hello" to server
		bzero(reply, BUF_SIZE);
		n = 0;
		cout<<"Write your message:\n";
		while((reply[n++] = getchar()) != '\n');
		write(sock, reply, BUF_SIZE);

		// client receives "chat_reply" from server
		bzero(response, BUF_SIZE);
		bytes_read = read(sock, response, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from server:\n"<<response;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// client sends "chat_STARTTLS" to server
		bzero(reply, BUF_SIZE);
		n = 0;
		cout<<"Write your message:\n";
		while((reply[n++] = getchar()) != '\n');
		write(sock, reply, BUF_SIZE);

		// client receives "chat_STARTTLS_ACK" from server
		bzero(response, BUF_SIZE);
		bytes_read = read(sock, response, BUF_SIZE);
		if(bytes_read > 0) {
			cout<<"Received from server:\n"<<response;
		} else {
			ERR_print_errors_fp(stderr);
		}

		// declaring SSL object
		SSL* ssl;

		// declaring SSL context object
		SSL_CTX* ctx;

		// creating SSL context
		ctx = create_context();
		cout<<"SSL context created...\n";
		// configuring SSL context by loading certs, keys,..
		configure_context(ctx);
		cout<<"Context configured...\n";

		// creating SSL object
		ssl = SSL_new(ctx);

		// setting file descriptor of conencting socket in ssl object
		SSL_set_fd(ssl, sock);

		// client tries to initiate the TLS/SSL handshake with a server
		if(SSL_connect(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		} else {
			// displaying peer certificates
			cout<<"Displaying peer certificates...\n";
			display_certificates(ssl);

			// returns the result of the verification of the X509 certificate presented by the peer
			if(SSL_get_verify_result(ssl) == X509_V_OK) {
			    cout<<"Certificate verification passed\n";
			} else {
				cout<<"Certificate verification failed\n";
			}

			// printing SSL version used in connection
			cout<<"SSL version used: ";
			cout<<SSL_get_version(ssl)<<endl;

			while(true) {
				// client sends message to server
				bzero(reply, BUF_SIZE);
				n = 0;
				cout<<"Write your message:\n";
				while((reply[n++] = getchar()) != '\n');
				SSL_write(ssl, reply, strlen(reply));

				// terminate connection if client sends chat_close
				if(!strcmp(reply, "chat_close\n")) break;
				
				// client receives message from server
				bzero(response, BUF_SIZE);
				bytes_read = SSL_read(ssl, response, BUF_SIZE);
				if(bytes_read > 0) {
					cout<<"Received from server:\n"<<response;
				} else {
					ERR_print_errors_fp(stderr);
				}
				// terminate connection if server sends chat_close
				if(!strcmp(response, "chat_close\n")) break;
			}
		}
		// close the socket 
		close(sock);
	}
	if (SSL_shutdown(ssl) == 0) {
        SSL_shutdown(ssl);
    }	
    cout<<"ok"<<endl;
	// reclaim the memory associated with ssl object
	SSL_free(ssl);
	// reclaim the memory associated with ssl context object
	SSL_CTX_free(ctx);
	// cleanup openssl loaded ciphers, algos, etc..
	cleanup_openssl();
	return 0;
}