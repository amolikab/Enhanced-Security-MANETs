//files required by send_new_certfiles
#define CERTFILE "node1.pem"
#define KEYFILE "node1key.pem"
#define CLIENT_CERT "client_cert.pem"

//files required by election_req_to_DCA
#define CLIENT_CSR "client_csr.pem"
#define ELECTED_CERTFILE_FROM_GOOD_NEIGH "elected_certfile_from_good_neigh.pem"

//files required by election_req_from_DCA
#define CERTFILE_OF_NEIGH_DCA_TO_VALIDATE "certfile_of_neigh_DCA_to_validate.pem"
#define SUPPORTING_CERTFILE_OF_NEIGH_DCA_TO_VALIDATE "supporting_certfile_of_neigh_DCA_to_validate.pem"

#define SUPPORTING_DCA_CERT_OF_NEIGH_DCA_TO_VALIDATE "supporting_dca_cert_of_neigh_DCA_to_validate.pem" //cert of DCA that helped to elect the DCA under consideration

#define NEIGH_DCA_CERT_TO_VALIDATE "dca_cert.pem"
#define CAFILE "rootcert.pem"
#define ELECTING_CSR_SENT_BY_NEIGH_DCA "electing_csr_sent_by_neigh_DCA.pem"
#define ELECTED_CERT_FOR_NEIGH_DCA "elected_cert_for_neigh_DCA.pem"
#define ELECTED_CERTFILE_FOR_NEIGH_DCA "elected_certfile_for_neigh_DCA.pem"

int check_elected_cert(SSL *ssl)
{
    //printf("Inside elected cert fcn\n");
    FILE *fp,*fp1,*fp_dca;
    int j=0;
    char line[256];
    fp_dca = fopen(SUPPORTING_DCA_CERT_OF_NEIGH_DCA_TO_VALIDATE,"w+");
    fp1 = fopen(NEIGH_DCA_CERT_TO_VALIDATE,"w+");
    fp = fopen(SUPPORTING_CERTFILE_OF_NEIGH_DCA_TO_VALIDATE,"r");
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
    snprintf(test,sizeof(test),"openssl verify -CAfile %s %s > %s", CAFILE, SUPPORTING_DCA_CERT_OF_NEIGH_DCA_TO_VALIDATE,"check_dca.txt");
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
    snprintf(verify_result1,sizeof(verify_result1),"%s: OK", SUPPORTING_DCA_CERT_OF_NEIGH_DCA_TO_VALIDATE);
    //puts(verify_result1);
    
    
    //To verify that current client is signed by supporting DCA signed by rootcert
    test[0] = '\0';
    snprintf(test,sizeof(test),"openssl verify -CAfile %s -untrusted %s %s > %s", CAFILE, SUPPORTING_DCA_CERT_OF_NEIGH_DCA_TO_VALIDATE, NEIGH_DCA_CERT_TO_VALIDATE, "check_whole_chain.txt");
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
    snprintf(verify_result2,sizeof(verify_result2),"%s: OK", NEIGH_DCA_CERT_TO_VALIDATE);
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
        fp1 = fopen(NEIGH_DCA_CERT_TO_VALIDATE,"r");
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

int check_dca_req_to_elect (SSL *ssl)
{
    printf("You are in the check fcn\n");
    X509 *cert = SSL_get_peer_certificate(ssl);
    int raw = X509_check_ca(cert);
    //to check the trust index to see if its a CA with TCA or DCA functions
    char *nid = certificate_parse(ssl);
    char x[50];
    strcpy(x,nid);
    printf("nid of DCA is : %s\n",x);    
    char a[50] = "..300";
    size_t len = strlen(x) -1; 
      
    
    FILE *fp;
    int bytesread;
    //read cert chain from the DCA
    printf("Recieving CERTFILE from the DCA\n");
    char buffer1[10000];
    bytesread = SSL_read(ssl,buffer1,sizeof(buffer1));
    buffer1[bytesread] = 0;        
    //Put cert chain in .pem file
    fp = fopen(CERTFILE_OF_NEIGH_DCA_TO_VALIDATE,"w+");
    fwrite(buffer1,sizeof(char),bytesread,fp);
    fclose(fp);
    //puts(buffer1);
    
    //check how many certificates in the chain
    fp = fopen(CERTFILE_OF_NEIGH_DCA_TO_VALIDATE,"r");
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
    
    //if CA:TRUE && cert_chain =2 ie DCA signed by root
    if ((raw >=1) && (n == 2) && (strncmp(x,a,len)==0 ))
    {   printf("Valid DCA\n");
        //write "ok" to DCA 
        char msg[] = "ok";     
        SSL_write(ssl,msg,strlen(msg));
        puts(msg);
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
        fp = fopen(SUPPORTING_CERTFILE_OF_NEIGH_DCA_TO_VALIDATE,"w+");
        fwrite(buffer2,sizeof(char),bytesread1,fp);
        fclose(fp);
        //puts(buffer2);
        
        int result = check_elected_cert(ssl);
        //int result = 1;
        if (result == 1)
        {    
            printf("Valid DCA\n");
            //write "ok" to DCA 
            char msg[] = "ok";     
            SSL_write(ssl,msg,strlen(msg));
            puts(msg);
            return 1;
        }  
        else
            return 0;  
    }
    else
        printf("Invalid chain\n");
    
    
    return 0;
}






int election_req_from_DCA (SSL *ssl)
{
    printf("You are in the election_req_from_DCA fcn\n");
    int x = check_dca_req_to_elect (ssl);
    if(x == 1)
    {
        //accept election request ie send positive response to the DCA
        printf("You replied\n ");
        char response[] = "Yes";   
        SSL_write(ssl,response,strlen(response));
        puts(response);  
        
        //recieve the CSR of the TCA to elect
        printf("Recieving CSR of the TCA to elect\n");
        char buffer[800];
        int bytesread = SSL_read(ssl,buffer,sizeof(buffer));
        buffer[bytesread] = 0;        
        //Put csr in .pem file
        FILE *fp = fopen(ELECTING_CSR_SENT_BY_NEIGH_DCA,"w+");
        fwrite(buffer,sizeof(char),bytesread,fp);
        fclose(fp);
        puts(buffer);
        
        //sign the csr of the candidate as a CA       
        char test[500]; 
        snprintf(test,sizeof(test),"openssl x509 -req -in %s -passin pass:dca1key -sha1 -extfile myopenssl.cnf -extensions v3_ca -CA %s -CAkey %s -CAcreateserial -out %s",ELECTING_CSR_SENT_BY_NEIGH_DCA,CERTFILE,KEYFILE,ELECTED_CERT_FOR_NEIGH_DCA);
        system(test);
        
        test[0] = '\0';
        snprintf(test,sizeof(test),"cat %s %s > %s",ELECTED_CERT_FOR_NEIGH_DCA, CERTFILE, ELECTED_CERTFILE_FOR_NEIGH_DCA );
        system(test);
        
        //put the signed certfile in a buffer           
        struct stat st;
        FILE *fp1 = fopen(ELECTED_CERTFILE_FOR_NEIGH_DCA,"r");
        stat(ELECTED_CERTFILE_FOR_NEIGH_DCA,&st);
        int buff_size1 = st.st_size;
        char certfile[buff_size1];
        if(fp1!=NULL)
        {
            size_t fileread = fread(certfile,sizeof(char),buff_size1,fp1);
            if(ferror(fp1))
                fprintf(stderr,"Error reading the file");
            else
                certfile[fileread++]='\0';
            fclose(fp1);
        }
        //write the cert to the TCA
        SSL_write(ssl,certfile,buff_size1);
        printf("finished writing to the DCA\n");
    }
    else
        int_error("Not a Valid DCA");
    
    
    return 1;
}


int election_req_to_DCA(SSL *ssl)
{
    check_dca(ssl);  
    
    //Wait for response from DCA to agree to help
    printf("Wait for response from DCA to agree to help\n");
    char reply[500];
    int bytesread;
    bytesread = SSL_read(ssl,reply,sizeof(reply));
    reply[bytesread] = 0; 
    char check_reply[]="Yes";
    printf("recieved from supporting DCA : ");
    puts(reply);
    if(strncmp(reply,check_reply,bytesread)==0)
    {
        printf("DCA accepted the request \n");
        
        //send CSR of the TCA to elect
        struct stat st;
        FILE *fp1 = fopen(CLIENT_CSR,"r");
        stat(CLIENT_CSR,&st);
        int buff_size = st.st_size;
        char csr[buff_size];
        if(fp1!=NULL)
        {
            size_t fileread = fread(csr,sizeof(char),buff_size,fp1);
            if(ferror(fp1))
                fprintf(stderr,"Error reading the file");
            else
                csr[fileread++]='\0';
            fclose(fp1);
        }
        //write the csr to the TCA
        SSL_write(ssl,csr,buff_size);
    
        //recieve the cert chain for elected TCA signed by the supporting DCA        
        printf("Recieving certfile from supporting DCA*\n");
        char certfile[5000];
        int certread;
        certread = SSL_read(ssl,certfile,sizeof(certfile));
        certfile[certread] = 0;
        puts(certfile);
    
        //Put cert in .pem file
        FILE *fp = fopen(ELECTED_CERTFILE_FROM_GOOD_NEIGH,"w+");
        fwrite(certfile,sizeof(char),certread,fp);
        fclose(fp);       
    }
    else
    {    
        printf("DCA rejected the request to elect\n");
        return 0;
    }
    return 1;
}


int send_new_certfiles(SSL *ssl)
{
    //sending supporting DCA certfile    
    printf("sending certfile to TCA to check my CA status\n");
    struct stat st;
    FILE *fp = fopen(ELECTED_CERTFILE_FROM_GOOD_NEIGH,"r");
    stat(ELECTED_CERTFILE_FROM_GOOD_NEIGH,&st);
    int buff_size = st.st_size;
    char buffer[buff_size];
    if(fp!=NULL)
    {
        size_t fileread = fread(buffer,sizeof(char),buff_size,fp);
        if(ferror(fp))
            fprintf(stderr,"Error reading the file");
        else
            buffer[fileread++]='\0';
        fclose(fp);
    }   
    SSL_write(ssl,buffer,strlen(buffer));
    //puts(buffer);
    

    //find the serial num
    char serial[500];
    get_serial_of_peer(ssl, serial);
    printf("Serial of the TCA is\n");
    puts(serial);   
        
    char test[500]; 
    //sign the csr of the candidate as a CA 
    snprintf(test,sizeof(test),"openssl x509 -req -in %s -passin pass:clientakey -sha1 -extfile myopenssl.cnf -extensions v3_ca -CA %s -CAkey %s -set_serial 0x%s -out %s",CLIENT_CSR,CERTFILE,KEYFILE,serial,CLIENT_CERT);
    system(test);   
        
    //put the signed cert in a buffer           
    struct stat st1;
    FILE *fp1 = fopen(CLIENT_CERT,"r");
    stat(CLIENT_CERT,&st1);
    int buff_size1 = st1.st_size;
    char cert[buff_size1];
    if(fp1!=NULL)
    {
        size_t fileread = fread(cert,sizeof(char),buff_size1,fp1);
        if(ferror(fp1))
            fprintf(stderr,"Error reading the file");
        else
            cert[fileread++]='\0';
        fclose(fp1);
    }
    //write the cert to the TCA
    SSL_write(ssl,cert,buff_size1);    
    printf("removing unwanted files\n");
    //remove used files
    test[0]='\0'; 
    snprintf(test,sizeof(test),"rm %s %s %s", CLIENT_CERT, CLIENT_CSR, ELECTED_CERTFILE_FROM_GOOD_NEIGH);
    system(test);
    return 1;
}   












