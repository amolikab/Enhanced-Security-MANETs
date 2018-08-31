#define ELECTED_CERT_CHAIN "elected_cert_chain.pem"
#define NEW_CA_CERT "new_ca_cert.pem"
#define CA_CERTFILE "ca_certfile.pem"   //acquired in add_client_tca.c
#define CAFILE "rootcert.pem"
#define CSR "node1req.pem"
#define CERTIFICATE "node1cert.pem"
#define CERTFILE "node1.pem"

int verify_elected_cert()
{
    //struct stat st1;
    //verify signed cert
    char test[100]; 
    snprintf(test,sizeof(test),"openssl x509 -in %s -pubkey -noout -outform pem | sha256sum > verifycert",NEW_CA_CERT);
    system(test);
    memset(&test[0],0,sizeof(test));
    snprintf(test,sizeof(test),"openssl req -in %s -pubkey -noout -outform pem | sha256sum > verifycsr",CSR);    
    system(test);
    memset(&test[0],0,sizeof(test));
    
    struct stat st1;
    FILE *fp2 = fopen("verifycert","r");
    stat(CSR,&st1);
    int buff_size = st1.st_size;
    char verifycert[buff_size];
    if(fp2!=NULL)
    {
        size_t fileread = fread(verifycert,sizeof(char),buff_size,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            verifycert[fileread++]='\0';
        fclose(fp2);
    }  
    
    
    fp2 = fopen("verifycsr","r");
    stat(CSR,&st1);
    int buff_size1 = st1.st_size;
    char verifycsr[buff_size1];
    if(fp2!=NULL)
    {
        size_t fileread = fread(verifycsr,sizeof(char),buff_size1,fp2);
        if(ferror(fp2))
            fprintf(stderr,"Error reading the file");
        else
            verifycsr[fileread++]='\0';
        fclose(fp2);
    }   
    
    if(strcmp(verifycert,verifycsr) == 0)
    {
        
        return 1;
    }
    else
        return 0;

    
}



int accept_new_certfiles(SSL *ssl)
{
    //Accept new chain from DCA
    int bytesread;
    printf("Recieving supporting CERTFILE from the DCA\n");
    char buffer[10000];
    bytesread = SSL_read(ssl,buffer,sizeof(buffer));
    buffer[bytesread] = 0;        
    //Put cert chain in .pem file
    FILE *fp = fopen(ELECTED_CERT_CHAIN,"w+");
    fwrite(buffer,sizeof(char),bytesread,fp);
    fclose(fp);
    //puts(buffer);
    
    //Accept new cert from DCA
    int bytesread1;
    printf("Recieving cert signed as CA from the DCA\n");
    char buffer1[10000];
    bytesread1 = SSL_read(ssl,buffer1,sizeof(buffer1));
    buffer1[bytesread1] = 0;        
    //Put cert chain in .pem file
    fp = fopen(NEW_CA_CERT,"w+");
    fwrite(buffer1,sizeof(char),bytesread1,fp);
    fclose(fp);
    //puts(buffer1);
    char test[500];
    int z = verify_elected_cert();
    snprintf(test,sizeof(test),"rm %s %s ","verifycsr","verifycert");
    system(test);
    if(z==1)
    {
        printf("Verified\n");
        test[0]='\0';
        snprintf(test,sizeof(test),"cat %s > %s ",NEW_CA_CERT, CERTIFICATE);    
        system(test);
        test[0]='\0';
        snprintf(test,sizeof(test),"cat %s %s > %s ",CERTIFICATE, CA_CERTFILE, CERTFILE);    
        system(test); 
    }
    else
        printf("Not Verified\n");
     
    return 1;
}
