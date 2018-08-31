#define CERTFILE "node1.pem"
#define KEYFILE "node1key.pem"
#define CLIENT_CSR "client_csr.pem"
#define CLIENT_CERT "client_cert.pem"
#define CLIENT_CERT_CHAIN "client_cert_chain.pem"
#define CERTIFICATE "node1cert.pem"
#define TCA_OF_NEW_CLIENT "tca_of_new_client.pem"

extern int serial_cert;
extern int num_clients;

int verify_TCA(void)
{
    //extract TCA cert to check the trust index
    FILE *fp,*fp_tca;
    int i = 0,j=0;
    fp = fopen(CLIENT_CERT_CHAIN,"r");
    char line[256];
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            i++;
    } 
    fclose(fp);
    fp_tca = fopen(TCA_OF_NEW_CLIENT,"w+");
    fp = fopen(CLIENT_CERT_CHAIN,"r");
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            j++;
        if( (j>2)    &&  (j<=4)  )    
            fprintf(fp_tca,"%s",line);         
    } 
    fclose(fp);
    fclose(fp_tca);
    
    char *nid;
    nid = pem_certificate_parse(TCA_OF_NEW_CLIENT);
    char x[50];
    strcpy(x,nid);
    printf("nid : %s\n",x);    
    //system("openssl x509 -in tca_of_new_client.pem -text");
    char a[50] = "..300";   //signed by a TCA
    char b[50] = "..400";   //signed by a TCA
    char c[50] = "..500";   //signed by a DCA no more in the network
    size_t len = strlen(x) -1; 
         
    if ((strncmp(x,a,len)==0 ) || ((strncmp(x,b,len)) ==0) || ((strncmp(x,c,len)) ==0) )
        return 1;  
    else
        return 0;  
    
}   



int issue_cert_for_tca(SSL *ssl, char *port)
{
    FILE *fp;
    int bytesread, bytesread1;
    //read csr from the client
    printf("Recieving csr from the client\n");
    char buffer[800];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put csr in .pem file
    fp = fopen(CLIENT_CSR,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    //puts(buffer);
        
    //send signed cert to the client
    char test[500]; 
    snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpC -CA %s -CAkey %s -set_serial 0x%d -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial_cert,CLIENT_CERT);
    system(test);
    
    serial_cert++;
    printf("sending signed cert to client\n");    
    struct stat st;
    FILE *fp1 = fopen(CLIENT_CERT,"r");
    stat(CLIENT_CERT,&st);
    int buff_size = st.st_size;
    char cert[buff_size];
    if(fp1!=NULL)
    {
        size_t fileread = fread(cert,sizeof(char),buff_size,fp1);
        if(ferror(fp1))
            fprintf(stderr,"Error reading the file");
        else
            cert[fileread++]='\0';
        fclose(fp1);
    }
    
    SSL_write(ssl,cert,buff_size);
    
    //puts(cert);
    
    //sending own CERTFILE to client
    
    FILE *fp2 = fopen(CERTFILE,"r");
    stat(CERTFILE,&st);
    int buff_size1 = st.st_size;
    char selfcert[buff_size1];
    if(fp2!=NULL)
    {
        size_t fileread1 = fread(selfcert,sizeof(char),buff_size1,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            selfcert[fileread1++]='\0';
        fclose(fp2);
    }
    
    SSL_write(ssl,selfcert,buff_size1);
    //puts(selfcert);
    
    //get the port number of the client
    
    printf("Recieving port num from client\n");
    char port1[500];
    bytesread1 = SSL_read(ssl,port1,sizeof(port1));
    port1[bytesread1] = 0;
    puts(port1); 
    strcpy(port,port1);
    puts(port);
    printf("check\n"); 
       
    return 1;
}



int add_client_dca(SSL *ssl)
{
    FILE *fp;
    int bytesread;
    //read cert chain from the client
    printf("Recieving CERTFILE from the client\n");
    char buffer[10000];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put cert chain in .pem file
    fp = fopen(CLIENT_CERT_CHAIN,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    //puts(buffer);
    int i = verify_TCA();
    printf("verify_TCA() id %d\n",i);
    if(i == 1)
    {
        printf("Trusted TCA, will sign and add as client\n");
        //respond to client
        char msg[] = "ok";    
        SSL_write(ssl,msg,strlen(msg));
        puts(msg);
        char port[500];
        issue_cert_for_tca(ssl,port);
        char serial[100];
        get_serial_from_cert(ssl,serial,"client_cert.pem");
        
        //int x = 123;
        //char serial[100] = x + '0';
        struct client *clientA = addnode(lastnode,serial,50,port);
        num_clients++;
        print_list(p->next);
        char test[500]; 
        snprintf(test,sizeof(test),"echo %s >> amo.txt",serial);
        system(test);       
    }
    else if(i == 0)
        printf("Cannot sign as TCA is not trusted enough\n");
    else
        printf("Invalid trust index\n");
    
    printf("removing unwanted files\n");
    //remove used files
    char test[500]; 
    snprintf(test,sizeof(test),"rm %s %s %s %s", CLIENT_CERT, CLIENT_CSR, CLIENT_CERT_CHAIN,TCA_OF_NEW_CLIENT);
    system(test);
    return 0;
}

