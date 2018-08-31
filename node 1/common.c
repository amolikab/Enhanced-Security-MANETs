#include "common.h"



struct client *addnode(struct client *clientAll,char *serial,int trust, char *port)
{
    struct client *clientA = (struct client*)malloc(sizeof(struct client));
    //struct client *p,*r;
    clientAll->next = clientA;
    strcpy(clientA->serial, serial);
    strcpy(clientA->port, port);
    clientA->trust = trust;
    clientA->next = NULL;
    lastnode = clientA;
    return clientA;
}

void print_list(struct client* q)
{
    while(q != NULL)
    {
        printf("Serial: %s  Trust: %d Port: %s\n",q->serial,q->trust,q->port);
        q = q->next;
    }
}

struct client* get_client_from_serial(struct client* list,char *serial)
{
    while(list != NULL)
    {
        //printf("Serial: %s  CSR:  Trust: %d\n",list->serial,list->trust);
        if(strcmp(list->serial,serial) == 0)
            return list;
        else
            list = list->next;              
    }    
}


void get_serial_from_cert(SSL *ssl, char *buff,char * pem_file)
{
    
    char file[100];
    strcpy(file,pem_file);
    FILE *fp = fopen(file,"r");
    X509 *cert = PEM_read_X509(fp,NULL,NULL,NULL);
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial,NULL);
    char *tmp = BN_bn2hex(bn);      
    strcpy(buff,tmp);
    BN_free(bn);
    OPENSSL_free(tmp);

}



void get_serial_of_peer(SSL *ssl, char *buff)
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial,NULL);
    char *tmp = BN_bn2hex(bn);      
    strcpy(buff,tmp);
    BN_free(bn);
    OPENSSL_free(tmp);
}


void handle_error(const char *file, int lineno, const char *msg)
{
    fprintf(stderr, "** %s:%i %s\n", file,lineno,msg);
    ERR_print_errors_fp(stderr);
    exit(-1);
}

void init_OpenSSL(void)
{
    if(! SSL_library_init())
    {
        fprintf(stderr,"**OpenSSL Initialization Failed! \n");
        exit(-1);
    }
    SSL_load_error_strings();
}

int verify_callback(int ok, X509_STORE_CTX *store)
{
    char data[256];
    
    if(!ok)
    {
        X509 *cert = X509_STORE_CTX_get_current_cert(store);
        int depth = X509_STORE_CTX_get_error_depth(store);
        int err = X509_STORE_CTX_get_error(store);
        
        fprintf(stderr, "Error with certificate at depth: %i\n",depth);
        
        X509_NAME_oneline(X509_get_issuer_name(cert),data, 256);
        fprintf(stderr, "Issuer = %s \n", data);
        
        X509_NAME_oneline(X509_get_subject_name(cert),data, 256);
        fprintf(stderr, "Subject = %s \n", data);
        fprintf(stderr, "err %i : %s \n", err, X509_verify_cert_error_string(err));
          
    }   
    
    return ok;   
}


char * pem_certificate_parse(char * pem_file)
{
    char file[100];
    strcpy(file,pem_file);
    FILE *fp = fopen(file,"r");
    X509 *cert = NULL;
    cert = PEM_read_X509(fp,NULL,NULL,NULL);
    if(cert == NULL)
        int_error("cannot read certificate");
           
    //to extract other extensions of the certificates
    STACK_OF(X509_EXTENSION) *ext = cert->cert_info->extensions;
    
    int num; //number of extensions
    char *data;
    if(ext)
        num = sk_X509_EXTENSION_num(ext);
    else
        num =0;
    
    if(num<0)
        int_error("error parsing number of extensions");
    
    for(int i = 0; i<num; i++)
    {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(ext,i);
        if( ex == NULL)
            int_error("Unable to extract extensions from the stack");
        
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);    
        if( obj== NULL)
            int_error("Unable to ASN1 object from extension");
        
        BIO *ext_bio = BIO_new(BIO_s_mem());
        if(ext_bio==NULL)
            int_error("unable to allocate mem for ext bio");
            
        if(!X509V3_EXT_print(ext_bio,ex,0,0))
            M_ASN1_OCTET_STRING_print(ext_bio,ex->value);
            
        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio,&bptr);
        BIO_set_close(ext_bio,BIO_NOCLOSE);
        
        BIO_free(ext_bio);
        
        int EXTNAME_LEN =100;
        
        unsigned nid = OBJ_obj2nid(obj);
        if(nid == NID_undef)
        {
            char extname[EXTNAME_LEN]; 
            OBJ_obj2txt(extname,EXTNAME_LEN,(const ASN1_OBJECT *)obj,1);
            //printf("Ext name is %s",extname);   
            //printf(" with value : %s\n",bptr->data);
            data = bptr->data;            
        }       
    }
    return data;
    printf("Back to pem certificate parse\n");
}

char * certificate_parse(SSL *ssl)
{
    X509 *cert = SSL_get_peer_certificate(ssl);
    if(cert == NULL)
        int_error("cannot read certificate");
           
    //to extract other extensions of the certificates
    STACK_OF(X509_EXTENSION) *ext = cert->cert_info->extensions;
    
    int num; //number of extensions
    char *data;
    if(ext)
        num = sk_X509_EXTENSION_num(ext);
    else
        num =0;
    
    if(num<0)
        int_error("error parsing number of extensions");
    
    for(int i = 0; i<num; i++)
    {
        X509_EXTENSION *ex = sk_X509_EXTENSION_value(ext,i);
        if( ex == NULL)
            int_error("Unable to extract extensions from the stack");
        
        ASN1_OBJECT *obj = X509_EXTENSION_get_object(ex);    
        if( obj== NULL)
            int_error("Unable to ASN1 object from extension");
        
        BIO *ext_bio = BIO_new(BIO_s_mem());
        if(ext_bio==NULL)
            int_error("unable to allocate mem for ext bio");
            
        if(!X509V3_EXT_print(ext_bio,ex,0,0))
            M_ASN1_OCTET_STRING_print(ext_bio,ex->value);
            
        BUF_MEM *bptr;
        BIO_get_mem_ptr(ext_bio,&bptr);
        BIO_set_close(ext_bio,BIO_NOCLOSE);
        
        BIO_free(ext_bio);
        
        int EXTNAME_LEN =100;
        
        unsigned nid = OBJ_obj2nid(obj);
        if(nid == NID_undef)
        {
            char extname[EXTNAME_LEN]; 
            OBJ_obj2txt(extname,EXTNAME_LEN,(const ASN1_OBJECT *)obj,1);
            //printf("Ext name is %s",extname);   
            //printf(" with value : %s\n",bptr->data);
            data = bptr->data;            
        }       
    }
    return data;
    printf("Back to certificate parse\n");
}




