#define CERTFILE "node1.pem"
#define ELECTED_CERT_CHAIN "elected_cert_chain.pem"


int check_dca (SSL *ssl)
{
    printf("You are in the check fcn to prove your are a DCA\n");
    
    //send CERTFILE to the TCA
    printf("sending certfile to peer to check my CA status\n");
    struct stat st;
    FILE *fp;
    fp = fopen(CERTFILE,"r");
    stat(CERTFILE,&st);
    int buff_size = st.st_size;
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
    SSL_write(ssl,buffer1,strlen(buffer1));
    //puts(buffer1);
    
    //wait for reply from TCA
    int bytesread1;
    printf("Recieving verdict from peer\n");
    char msg[100];
    bytesread1 = SSL_read(ssl,msg,sizeof(msg));
    msg[bytesread1] = 0;
    puts(msg);  
    char ok[] = "ok";
    char send_other[] = "send more";
    
    if(strncmp(msg,ok,bytesread1)==0)
    {
        printf("peer accepts this DCA \n");
        return 1;
    }
    else if(strncmp(msg,send_other,bytesread1)==0)
    {
        printf("peer wants to recieve the other cert chains \n");
        //send other CERTFILE of the DCAs that agreed to elect me to the requesting TCA
        printf("sending certfile to peer to check my CA status\n");
        struct stat st1;
        FILE *fp1 = fopen(ELECTED_CERT_CHAIN,"r");
        stat(ELECTED_CERT_CHAIN,&st1);
        int buff_size1 = st1.st_size;
        printf("buff_size1 %d\n", buff_size1);
        char buffer2[buff_size1];
        if(fp1!=NULL)
        {
            size_t fileread = fread(buffer2,sizeof(char),buff_size1,fp1);
            if(ferror(fp1))
                fprintf(stderr,"Error reading the file");
            else
                buffer2[fileread++]='\0';
            fclose(fp1);
        }   
        //puts(buffer2);
        SSL_write(ssl,buffer2,strlen(buffer2));
        puts(buffer2);
      
        //wait for reply from TCA
        int bytesread;
        printf("Recieving verdict from peer\n");
        char buffer3[100];
        bytesread = SSL_read(ssl,buffer3,sizeof(buffer3));
        buffer3[bytesread] = 0;
        puts(buffer3);  
            
        if(strncmp(buffer3,ok,bytesread)==0)
        {
            printf("peer accepts this DCA \n");
            return 1;
        }
        else
        {
            printf("peer rejects this DCA \n");
            return 0;
        }
    }
    return 0;
}










