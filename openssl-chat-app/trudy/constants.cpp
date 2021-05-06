#include <string.h>
#include <iostream>
using namespace std;

const char* SERVER_CERT_FILE_NAME = "fakebob.crt";
const char* SERVER_KEY_FILE_NAME = "root.pem";

const char* CLIENT_CERT_FILE_NAME = "fakealice.crt";
const char* CLIENT_KEY_FILE_NAME = "root.pem";

int BUF_SIZE = 1024;

int MAX_CONNECTIONS_SERVER_LISTEN = 1;

int SERVER_LISTEN_PORT = 3000;

int MITM_LISTEN_PORT = 3500;
