#define CLIENT_CSR "client_csr.pem"
#define CERTFILE "node1.pem"
#define KEYFILE "node1key.pem"
#define CLIENT_CERT "client_cert.pem"

int reissue_dca_peer(SSL *ssl)
{
    FILE *fp;
    int bytesread,election;
    //read csr from the client
    printf("Recieving CSR from the TCA\n");
    char buffer[800];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put csr in .pem file
    fp = fopen(CLIENT_CSR,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    puts(buffer);
      
    //find the serial num
    char serial[500];
    get_serial_of_peer(ssl, serial);
    printf("Serial of the TCA is\n");
    puts(serial);   
    
    //char serial[500] = "01";
    //puts(serial); 
    //get client trust from serial
    struct client *client_to_reissue = get_client_from_serial(p,serial);
    int trust = client_to_reissue->trust;
    printf("the current trust of %s is %d \n",serial,trust);
    
    if(trust<10)
    {
        //reissue cert in grp A ie expell the node from network
        char test[500]; 
        snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpA -CA %s -CAkey %s -set_serial 0x%s -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial,CLIENT_CERT);
        system(test); 
        election =0;   
    }
    else if(trust<25)
    {
        //reissue cert in grp B
        char test[500]; 
        snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpB -CA %s -CAkey %s -set_serial 0x%s -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial,CLIENT_CERT);
        system(test); 
        election =0;   
    }
    else if((trust >= 25) && (trust <= 75)) 
    {
        //reissue cert in grp C
        char test[500]; 
        snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpC -CA %s -CAkey %s -set_serial 0x%s -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial,CLIENT_CERT);
        system(test); 
        election =0;    
    }
    else if(trust>75)
    {
        //check if to be re-issued in grpD or v3_ca
        char *nid = certificate_parse(ssl);
        char x[50];
        strcpy(x,nid);
        printf("nid of DCA is : %s\n",x);    
        char a[50] = "..300";
        char b[50] = "..400";
        char c[50] = "..500";
        size_t len = strlen(x) -1;
        
        if ( (strncmp(x,a,len)==0) || (strncmp(x,b,len)==0) )
        {
            //to be reissued to grpD and eligible for election
            char test[500]; 
            //but first sign with grp D until election process is over
            snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile myopenssl.cnf -extensions usr_cert_grpD -CA %s -CAkey %s -set_serial 0x%s -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial,CLIENT_CERT);
            system(test);
            election = 1;
        }
        else if (strncmp(x,c,len)==0)
        {
            //already a DCA, just reissue in v3_ca
            char test[500]; 
            snprintf(test,sizeof(test),"openssl x509 -req -in %s -sha1 -extfile myopenssl.cnf -extensions v3_ca -CA %s -CAkey %s -set_serial 0x%s -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial,CLIENT_CERT);
            system(test); 
            election =0;    
        }
                   
    } 
       
    //put the signed cert in a buffer           
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
    //write the cert to the TCA
    SSL_write(ssl,cert,buff_size);
    
    if (election == 1) 
        return 1;
    else
        return 0;
}











