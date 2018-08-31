//Node 1 Code

#include "common.c"
#include "add_client_dca.c"
#include "update_dca.c"
#include "reissue_dca_peer.c"
#include "check_dca.c"
#include "election_req.c"
#include "add_client_tca.c"
#include "update_tca.c"
#include "reissue_tca.c"
#include "check_tca.c"
#include "accept_new_certfiles.c"

#define CIPHER_LIST "ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH"
#define CAFILE "rootcert.pem"
#define CADIR NULL
#define CERTFILE "node1.pem"
#define KEYFILE "node1key.pem"


struct client *p;
struct client *lastnode;
int num_updates = 0;
int num_clients = 0;
int serial_cert = 1; //global var to set the serial nums of the TCAs requesting to register to this DCA (used in add_client_dca)
int elect = 0;      //Bool var to determine if TCA is eligible to be elected
int election_bool = 0; //Bool var to determine if TCA has accepted elegibility request
int elected_certfile = 0;//Bool var to determine if DCA has gained vote from another DCA
int num_of_neigh_DCA = 1;
char *neigh_DCA_port[] = {"7001"}; //array to store the ports of neigh DCAs 
                                          //to send electionrequests



//fcn to set the values of the context that will be inherited by the SSL connection
SSL_CTX *setup_ctx(void)
{
    SSL_CTX *ctx;
    ctx = SSL_CTX_new(SSLv23_method());
    
    if(SSL_CTX_load_verify_locations(ctx,CAFILE,CADIR) != 1)
        int_error("Error loading CA file");
        
    if(SSL_CTX_set_default_verify_paths(ctx) != 1)
        int_error("Error loading default CA file");    
    
    if(SSL_CTX_use_certificate_chain_file(ctx,CERTFILE) != 1)
        int_error("Error loading certificate from file");
        
    if(SSL_CTX_use_PrivateKey_file(ctx,KEYFILE,SSL_FILETYPE_PEM) != 1)
        int_error("Error loading private key from file");
        
    SSL_CTX_set_verify(ctx,SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);
    
    SSL_CTX_set_verify_depth(ctx,4);
    SSL_CTX_set_options(ctx,SSL_OP_ALL|SSL_OP_NO_SSLv2);
    if(SSL_CTX_set_cipher_list(ctx, CIPHER_LIST) != 1)
        int_error("Error setting cipher list (no valid ciphers)");
    return ctx;
}


int do_client_loop (SSL *ssl,char *msg,char *myport)
{
    int byteswritten,err,bytesread;
    
    //receive welcome from the server
    printf("Recieving from peer\n");
    char buffer[500];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;
    puts(buffer);
    
    //write ur choice
    SSL_write(ssl,msg,strlen(msg));
    //when acting as a DCA
    char reissue_for_dca[] = "1";       //option to send to a TCA
    char eligibility_request[] = "2";   //option to send to a TCA
    char new_certfiles_to_tca[] = "3";     //option to send to a TCA
    char election_request_to_neigh_dca[] = "5";  //option to send to a DCA
    //when acting as a TCA    
    char check_validity_of_dca[] = "6";
    char new_client_request[] = "7";
    char reissue_request_to_dca[] = "8";
    char send_update[] = "4";
    
    if(strncmp(msg,reissue_for_dca,strlen(msg))==0)
    {
        printf("You chose reissue fcn\n");
        int x = reissue_dca_peer(ssl);
        if (x == 1)
            elect = 1;
    }
    else if(strncmp(msg,eligibility_request,strlen(msg))==0)
    {
        printf(" send eligibility_request to TCA\n");
        char request[] = "Can you become a DCA?";    
        SSL_write(ssl,request,strlen(request));
        puts(request);
        //getting reply from TCA
        printf("get eligibility_reply from TCA\n");
        char reply[500];
        int bytesread;
        bytesread = SSL_read(ssl,reply,sizeof(reply));
        reply[bytesread] = 0; 
        char check_reply[]="Yes";
        printf("recieved from server : ");
        puts(reply);
        if(strncmp(reply,check_reply,bytesread)==0)
        {
            printf("TCA accepted the request \n");
            //send eligibility to other DCAs
            election_bool = 1;
        }
        else
            printf("TCA cannot be a DCA\n");
    }
    else if(strncmp(msg,new_certfiles_to_tca,strlen(msg))==0)
    {
        printf("You chose to send new certfiles to the TCA\n");
        send_new_certfiles(ssl);
        printf("end of new certfiles (client thread)\n");        
    }
    else if(strncmp(msg,election_request_to_neigh_dca,strlen(msg))==0)
    {
        printf("You chose to send election_request to other DCAs\n");
        int x = election_req_to_DCA(ssl);
        if (x ==1)
            elected_certfile = 1;            
    }    
    //when acting as a TCA
    else if (strncmp(msg,check_validity_of_dca,strlen(msg))==0)
    {
        printf("You chose to verify the DCA\n");
        int r = check_tca(ssl);
        if(r != 1)
            int_error("Not a reliable DCA");
    } 
    else if (strncmp(msg,new_client_request,strlen(msg))==0)
    {
        printf("You chose new_client fcn\n");
        add_client_tca(ssl,myport);
    } 
    else if(strncmp(msg,reissue_request_to_dca,strlen(msg))==0)
    {
        printf("You send reissue request to the DCA\n");
        reissue_tca(ssl);
    }
    else if (strncmp(msg,send_update,strlen(msg))==0)
    {
        printf("You chose update fcn\n");
        update_tca(ssl);
    }   
    else
        int_error("Invalid choice");
       
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1:0;

}


void *client_thread(SSL_CTX *ctx, char * option, char *ca_port, char *myport)
{
    //SSL_CTX *ctx = (SSL_CTX *)arg;
    BIO *cbio;
    SSL *c_ssl;
    char x[] = ":";
    char *site = malloc(strlen(ca_port)+strlen(SERVER)+strlen(x)+1);
    strcpy(site,SERVER);
    strcat(site,x);
    strcat(site,ca_port);
    cbio = BIO_new_connect(site);   
    if(!cbio)
        int_error("Error creating connection BIO for client ");
        
    if(BIO_do_connect(cbio) <= 0)
        int_error("Error connectiong to remote machine ");
    
    //this command stores the newly signed/reissued cert into the ssl connection
    if(SSL_CTX_use_certificate_chain_file(ctx,CERTFILE) != 1)
        int_error("Error loading certificate from file");   
     
    if(!(c_ssl = SSL_new(ctx)))
        int_error("Error creating SSL context for client");
            
    SSL_set_bio(c_ssl,cbio,cbio);
    
    if (SSL_connect(c_ssl) <= 0)
        int_error ("Error connecting SSL object");
    
    fprintf(stderr,"SSL Connection Opened \n");
        
    if(do_client_loop(c_ssl,option,myport))
        SSL_shutdown(c_ssl);
    else
        SSL_clear(c_ssl);    
    
    fprintf(stderr,"SSL Connection Closed \n");
    
    SSL_free(c_ssl);
    free(site);
    ERR_remove_state(0);
    
}



//This fcn is used to send requests to the DCA.
void * client(void *arg)
{
    struct thread_arg *arguments = (struct thread_arg*)arg;
    SSL_CTX *ctx = arguments->ctx;
    char *ca_port = arguments->ca_port;
    char *myport = arguments->myport;
    
    client_thread(ctx,"6",ca_port,myport);    //check   
    sleep(5);
    
    client_thread(ctx,"7",ca_port,myport);    //new client   
    sleep(10);
                                
    for(int i = 0;i<10;i++)     //update   
    {
        client_thread(ctx,"4",ca_port,myport);
        sleep(5);
    }    
    client_thread(ctx,"8",ca_port,myport);    //reissue   
    sleep(15);
    //updates for 4 clients
    for(int i = 0;i<10;i++)     //update  
    {
        client_thread(ctx,"4",ca_port,myport);
        sleep(5);
    } 
    sleep(15);
    //updates for 6 clients
    for(int i = 0;i<10;i++)     //update  
    {
        client_thread(ctx,"4",ca_port,myport);
        sleep(5);
    } 
           
}




int do_server_loop(SSL *ssl)
{
    
    int bytesread, err,x,byteswritten,bytesread1;  
    
    //write to peer
    char msg[] = "*******Welcome to the Listening port of Node 1! ********";     
    SSL_write(ssl,msg,strlen(msg));
    puts(msg);
      
     //receive choice from the peer
    printf("Recieving from peer\n");
    char buff[100];
    bytesread1 = SSL_read(ssl,buff,sizeof(buff));
    buff[bytesread1] = 0;
    puts(buff); 
    //Server options when acting as a DCA 
    char update_from_tca[] = "4";    
    char election_request_from_neigh_dca[] = "5";
    char check_my_validity[] = "6";
    char add_new_client[] = "7";
    char reissue_from_tca[] = "8";
    
    //Server options when acting as a TCA
    char reissue_for_tca[] = "1";
    char eligibility_request_from_dca[] = "2";
    char accept_new_certfiles_from_dca[] = "3";
      
    
    if(strncmp(buff,check_my_validity,bytesread1)==0)
    {
        printf("TCA wants to check this DCA \n");
        check_dca(ssl);
    }
    else if(strncmp(buff,add_new_client,bytesread1)==0)
    {
        printf("TCA wants to add_new_client \n");
        add_client_dca(ssl);
    }
    else if(strncmp(buff,reissue_from_tca,bytesread1)==0)
    {
        printf("Goto reissue fcn\n");
        reissue_dca_peer(ssl);                     
    }
    else if (strncmp(buff,update_from_tca,bytesread1)==0)
    {
        printf("Goto update fcn\n");
        char * a[10] ;//list of all port numbers to reissue
        int x = update_dca(ssl,a);
        //After the update if any node changes its reputation group, its ccertificate needs tp be reissued accordingly
        printf("the clients to reissue are:\n");
        if(x>0)
        {
            char *port;
            for(int i = 0;i<x;i++)
            {    
                port = a[i];
                puts(port);
                SSL_CTX *ctx = setup_ctx();
                client_thread(ctx,"1",port,NULL);
                if (elect == 1)
                {   //need to elect
                    printf("this TCA is eligible for election at the port %s\n",port);
                    SSL_CTX *ctx = setup_ctx();
                    client_thread(ctx,"2",port,NULL);
                    printf("Back to reissue_dca_peer\n");
                    if(election_bool == 1)
                    {
                        printf("TCA has agreed, send election details to other DCAs\n");
                        char *DCA_port;
                        for(int i = 0;i < num_of_neigh_DCA; i++)
                        {                   
                            DCA_port = neigh_DCA_port[i];
                            client_thread(ctx,"5",DCA_port,NULL);
                            if(elected_certfile == 1)
                            {
                                //Successfully acquired a vote from the neigh DCA
                                client_thread(ctx,"3",port,NULL);
                                elected_certfile = 0;                            
                            }                    
                        }
                        election_bool = 0;
                    }    
                    printf("finish electing\n");
                    elect = 0;
                } 
            }   
        }       
    }
     
    else if (strncmp(buff,election_request_from_neigh_dca,bytesread1)==0)
    {
        printf("Goto election_req_from_DCA fcn\n");
        election_req_from_DCA(ssl);
    } 
    //When node acts like TCA
    else if(strncmp(buff,reissue_for_tca,bytesread1)==0)
    {
        printf("DCA wants to reissue cert\n");
        reissue_tca(ssl);          
    }
    else if(strncmp(buff,eligibility_request_from_dca,bytesread1)==0)
    {
        printf("get eligibility_request from DCA\n");
        char request[500];
        int bytesread;
        bytesread = SSL_read(ssl,request,sizeof(request));
        request[bytesread] = 0; 
        char check_request[]="Can you become a DCA?";
        printf("recieved from server : ");
        puts(request);
        if(strncmp(request,check_request,bytesread)==0)
        {
            //Can u become a DCA?
            printf("You replied\n ");
            char response[] = "Yes";   //reply "No" if not capable of handling computatns
            SSL_write(ssl,response,strlen(response));
            puts(response);  
                                            
        }
        
        else
            int_error("Unexpected msg from DCA");
      
    }
    else if(strncmp(buff,accept_new_certfiles_from_dca,bytesread1)==0)
    {
        printf("DCA wants to send new certfiles to act as a CA\n");
        accept_new_certfiles(ssl);          
    }
       
    else
        printf("choose better\n");
        
    
    return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1:0;

}


//This fcn is used to create multiple threads within the server thread so that it can handle many clients simultaneously
void *server_thread(void *arg)
{
    pthread_mutex_lock(&lock);//to avoid 2 or more clients to cause change in the DCA reputation table database at the same time
    
    SSL *s_ssl = (SSL *)arg;
    
    if (SSL_accept(s_ssl) <= 0)
        int_error ("Error accepting SSL connection");
    
    fprintf(stderr,"SSL Connection Opened \n");
        
    if(do_server_loop(s_ssl))
        SSL_shutdown(s_ssl);
    else
        SSL_clear(s_ssl);    
    
    fprintf(stderr,"SSL Connection Closed \n");
    
    SSL_free(s_ssl);
    ERR_remove_state(0);
    
    pthread_mutex_unlock(&lock);
}


void *server(void *arg)
{
    BIO *client,*sbio;
    struct thread_arg *arguments = (struct thread_arg*)arg;
    SSL_CTX *ctx = arguments->ctx;
    char *myport = arguments->myport;
    THREAD_TYPE nodes[NUM_CLIENTS];
    
    SSL *s_ssl;
    int i =0;
    
    //MUTEX
    if (pthread_mutex_init(&lock, NULL) != 0)
    {
        printf("\n mutex init failed\n");
    }
    
    sbio = BIO_new_accept(myport);  
    if(!sbio)
        int_error("Error creating server socket");
        
    if(BIO_do_accept(sbio) <= 0)
        int_error("Error binding server socket");
    
    while(i<100)//100 is number of approx threads that can be created within this thread
    {
    if(BIO_do_accept(sbio) <= 0)
        int_error("Error accepting connection");
    
    client = BIO_pop(sbio);
        
    if(!(s_ssl = SSL_new(ctx)))
        int_error("Error creating SSL context for Server");
      
    SSL_set_bio(s_ssl,client,client);    
    
    //Server thread
    printf("Creating the server_thread inside\n");   
    pthread_create(&(nodes[i]), NULL,&server_thread, s_ssl); 
    i++;
    }
    
    //make sure thread join the main thread after they are finished
    for(int j = 0; j<i; j++)
        pthread_join((nodes[j]),NULL);
    
    pthread_mutex_destroy(&lock);
}

//This server thread is only created for the purpose of maintaing logs during execution
void *network(void *arg)
{
    char test[500]; 
    int i=0;
    for(;;)
    {
    sleep(10);
    test[0] = '\0';
    snprintf(test,sizeof(test),"echo at time %ds num of clients %d >> network.txt",i, num_clients);
    system(test);
    
    test[0] = '\0'; 
    snprintf(test,sizeof(test),"echo %d %d >> no_of_clients.txt",i,num_clients);
    system(test);
           
    i = i+10;
    }
}


int main(int argc,char *argv[])
{
    struct client list;
    p = &list;
    p->next = NULL;
    lastnode = p;
    printf("This is Node 1 of Cluster 1\n");
    
    SSL_CTX *ctx;
    char *myport = argv[1];
    char *ca_port = argv[2];
    THREAD_TYPE tid[10]; 
    struct thread_arg arg;    
    int i = 0;
    init_OpenSSL();  /// initializing the ssl config files
    ctx = setup_ctx();
    arg.ctx = ctx;
    arg.myport = myport;
    arg.ca_port = ca_port;
    
    //Server thread first
    printf("Creating the server_thread outside\n");   
    pthread_create(&(tid[i]), NULL,&server, &arg); 
    i++;
    
    printf("Creating thread to print num of clients in network\n");   
    pthread_create(&(tid[i]), NULL,&network, &arg); 
    i++; 
     
    //Client thread
    printf("Creating the client_thread\n");   
    pthread_create(&(tid[i]), NULL,&client, &arg);
    i++;
     
    //make sure thread join the main thread after they are finished
    for(int j = 0; j<i; j++)
        pthread_join((tid[j]),NULL);
    
    SSL_CTX_free(ctx);

    struct client* curr;
    struct client* s = p->next;
    while((curr = s)!= NULL)
    {
        s = s->next;
        free(curr);    
    }    
}


















