#define CERT_CHAIN_DCA "cert_chain_dca.pem"
#define CERT_CHAIN_DCA_OTHER "cert_chain_dca_other.pem"
#define SUPPORTING_DCA "supporting_dca.pem"
#define CLIENT_CERT1 "client_cert1.pem"
#define CAFILE "rootcert.pem"

int check_elected_cert_of_dca(SSL *ssl)
{
    //printf("Inside elected cert fcn\n");
    FILE *fp,*fp1,*fp_dca;
    int j=0;
    char line[256];
    fp_dca = fopen(SUPPORTING_DCA,"w+");
    fp1 = fopen(CLIENT_CERT1,"w+");
    fp = fopen(CERT_CHAIN_DCA_OTHER,"r");
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            j++;
        if( (j>0)    &&  (j<=2)  )    
            fprintf(fp1,"%s",line);
        if( (j>2)    &&  (j<=4)  )    
            fprintf(fp_dca,"%s",line);         
    } 
    fclose(fp);
    fclose(fp1);
    fclose(fp_dca);
    
    //To verify that supporting DCA cert signed by rootcert
    char test[500]; 
    snprintf(test,sizeof(test),"openssl verify -CAfile %s %s > %s", CAFILE, SUPPORTING_DCA,"check_dca.txt");
    system(test);
    //save the result from file to buffer
    struct stat s1;
    fp = fopen("check_dca.txt","r");
    stat("check_dca.txt",&s1);
    int buff_size = s1.st_size;
    char buffer1[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buffer1,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buffer1[fileread++]='\0';
        fclose(fp);
    }  
    //puts(buffer1);
    int len1 = strlen(buffer1)-1;
        
    //to check the result of above command
    char verify_result1[500]; 
    snprintf(verify_result1,sizeof(verify_result1),"%s: OK", SUPPORTING_DCA);
    //puts(verify_result1);
    
    
    //To verify that current client is signed by supporting DCA signed by rootcert
    test[0] = '\0';
    snprintf(test,sizeof(test),"openssl verify -CAfile %s -untrusted %s %s > %s", CAFILE, SUPPORTING_DCA,CLIENT_CERT1,"check_whole_chain.txt");
    system(test);
    //save the result from file to buffer
    struct stat s2;
    fp1 = fopen("check_whole_chain.txt","r");
    stat("check_whole_chain.txt",&s2);
    buff_size = s2.st_size;
    char buffer2[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buffer2,sizeof(char),buff_size,fp1);
        if(ferror(fp1))
            fprintf(stderr,"Error reading the file");
        else
            buffer2[fileread++]='\0';
        fclose(fp1);
    }  
    //puts(buffer2);
    int len2 = strlen(buffer2)-1;
    
    //to check the result of above command
    char verify_result2[500]; 
    snprintf(verify_result2,sizeof(verify_result2),"%s: OK", CLIENT_CERT1);
    //puts(verify_result2);
    
    //to compare the results
    if(   (strncmp(buffer1,verify_result1,len1) == 0) && (strncmp(buffer2,verify_result2,len2) == 0)   )
    {    //printf("verified the elected chain \n");   
        //To verify that the public key in both the cert of investigating DCA is the same
        //peer cert
        X509 *cert = SSL_get_peer_certificate(ssl);
        EVP_PKEY *pkey = X509_get_pubkey(cert);
        RSA *rsa_key = pkey->pkey.rsa;
        char *rsa_n_hex = BN_bn2hex(rsa_key->n);
        char *rsa_e_dec = BN_bn2dec(rsa_key->e);
        //printf("Public key of peer\n");
        //puts(rsa_n_hex);
        //puts(rsa_e_dec);
        EVP_PKEY_free(pkey);
        
        //elected cert
        fp1 = fopen(CLIENT_CERT1,"r");
        X509 *cert1 = PEM_read_X509(fp1,NULL,NULL,NULL);
        EVP_PKEY *pkey1 = X509_get_pubkey(cert1);
        RSA *rsa_key1 = pkey1->pkey.rsa;
        char *rsa_n_hex1 = BN_bn2hex(rsa_key1->n);
        char *rsa_e_dec1 = BN_bn2dec(rsa_key1->e);
        //printf("public key of additional peer\n");
        //puts(rsa_n_hex1);
        //puts(rsa_e_dec1);
        EVP_PKEY_free(pkey1);
        
        if(  (strcmp(rsa_n_hex,rsa_n_hex1) == 0) && (strcmp(rsa_e_dec,rsa_e_dec1) == 0)  )  
            return 1;
            //printf("public key of both cert confirmed\n");
        else
            return 0;
    }
    else
        return 0;    
}

int check_tca (SSL *ssl)
{
    printf("You are in the check fcn to validate the DCA\n");
    X509 *cert = SSL_get_peer_certificate(ssl);
    int raw = X509_check_ca(cert);
    //to check the trust index to see if its a CA with TCA or DCA functions
    char *nid;
    nid = certificate_parse(ssl);
    char x[50];
    strcpy(x,nid);
    printf("nid of DCA is : %s\n",x);    
    char a[50] = "..500";
    size_t len = strlen(x) -1; 
      
    FILE *fp;
    int bytesread;
    //read cert chain from the DCA
    printf("Recieving CERTFILE from the DCA\n");
    char buffer1[10000];
    bytesread = SSL_read(ssl,buffer1,sizeof(buffer1));
    buffer1[bytesread] = 0;        
    //Put cert chain in .pem file
    fp = fopen(CERT_CHAIN_DCA,"w+");
    fwrite(buffer1,sizeof(char),bytesread,fp);
    fclose(fp);
    //puts(buffer1);
    
    //check how many certificates in the chain
    fp = fopen(CERT_CHAIN_DCA,"r");
    char line[256];
    int i = 0;
    while(fgets(line,sizeof(line),fp))
    {
        if(line[0] == '-')
            i++;
    } 
    fclose(fp);
    int n = i/2; 
    printf("there are %d certificates in the chain\n",n);
    
    //if CA:TRUE && cert_chain =2 ie DCA signed by root with nid = 500
    if ((raw >=1) && (n == 2) && (strncmp(x,a,len)==0 ))
    {   printf("Valid DCA\n");
        //write "ok" to DCA 
        char msg[] = "ok";     
        SSL_write(ssl,msg,strlen(msg));
        puts(msg);
        system("rm cert_chain_dca.pem");
        return 1;        
    }
    else if ((raw >=1) && (n == 3) && (strncmp(x,a,len)==0 ))  //elected DCA
    {   printf("Elected DCA\n");
        //write "send more" to DCA 
        char msg[] = "send more";     
        SSL_write(ssl,msg,strlen(msg));
        puts(msg);
        
        //Accept new chain form DCA
        int bytesread1;
        printf("Recieving second CERTFILE from the DCA\n");
        char buffer2[10000];
        bytesread1 = SSL_read(ssl,buffer2,sizeof(buffer2));
        buffer2[bytesread1] = 0;        
        //Put cert chain in .pem file
        fp = fopen(CERT_CHAIN_DCA_OTHER,"w+");
        fwrite(buffer2,sizeof(char),bytesread1,fp);
        fclose(fp);
        //puts(buffer2);
        
        int result = check_elected_cert_of_dca(ssl);
        printf("removing unwanted files\n");
        //remove used files
        char test[500]; 
        snprintf(test,sizeof(test),"rm %s %s %s %s %s", CERT_CHAIN_DCA_OTHER, SUPPORTING_DCA, CLIENT_CERT1,"check_dca.txt","check_whole_chain.txt");
        system(test);
        //int result = 1;
        
        if (result == 1)
        {    
            printf("Valid DCA\n");
            //write "ok" to DCA 
            char msg[] = "ok";     
            SSL_write(ssl,msg,strlen(msg));
            puts(msg);
            system("rm cert_chain_dca.pem");
            return 1;
        }  
        else
        {
            system("rm cert_chain_dca.pem");
            return 0;
        }      
    }
    else
    {   printf("Invalid chain, rejecting DCA\n");
        //write "reject" to DCA 
        char msg[] = "reject";     
        SSL_write(ssl,msg,strlen(msg));
        puts(msg);
        system("rm cert_chain_dca.pem");
        return 0;
    }
    
}










