#include<openssl/bio.h>
#include<openssl/err.h>
#include<openssl/rand.h>
#include<openssl/ssl.h>
#include<openssl/x509v3.h>
#include<pthread.h>
#include<sys/stat.h>
#include <stdio.h>
#include<unistd.h>

#define THREAD_TYPE pthread_t
#define THREAD_CREATE(tid,entry,arg) pthread_create(&(tid),NULL,entry,arg)
//#define PORT "6001"
#define SERVER "127.0.0.1"
#define CLIENT 
#define NUM_CLIENTS 100

void handle_error(const char *file, int lineno, const char *msg);

#define int_error(msg) handle_error(__FILE__, __LINE__, msg)

void init_OpenSSL(void);
int verify_callback(int ok, X509_STORE_CTX *store);
struct client
{
    char serial[200];
    int trust;
    char port[500];
    struct client *next;
};
struct client *addnode(struct client *clientAll,char *serial,int trust,char *port);
void print_list(struct client* q);
struct client* get_client_from_serial(struct client* list,char *serial);
extern struct client *p;
extern struct client *lastnode;
void get_serial_from_cert(SSL *ssl, char *buff,char * pem_file);
void get_serial_of_peer(SSL *ssl, char *buff);
struct thread_arg
{
    SSL_CTX *ctx;
    char *myport;
    char *ca_port;
};

pthread_mutex_t lock;
char * pem_certificate_parse(char * pem_file);







