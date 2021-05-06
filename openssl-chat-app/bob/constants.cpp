#include <string.h>
#include <iostream>
using namespace std;

const char* SERVER_CERT_FILE_NAME = "bob.crt";
const char* SERVER_KEY_FILE_NAME = "bob-private.pem";

const char* CLIENT_CERT_FILE_NAME = "alice.crt";
const char* CLIENT_KEY_FILE_NAME = "alice-private.pem";

int BUF_SIZE = 1024;

int MAX_CONNECTIONS_SERVER_LISTEN = 1;

int SERVER_LISTEN_PORT = 3000;

int MITM_LISTEN_PORT = 3500;
