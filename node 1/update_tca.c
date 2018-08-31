#define LIST3 "update3.txt"
#define LIST4 "update4.txt"
#define LIST6 "update6.txt"
extern int num_updates;

int update_tca(SSL *ssl)
{
    printf("You want to send update info to DCA\n");
    
    if (num_updates <=10)
    {
    printf("You want to send update of 2 neigh\n");
    //sending update list to server
    FILE *fp = fopen( LIST3,"r");
    struct stat st;
    stat(LIST3,&st);
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
    puts(buffer);
    num_updates++;
    }
    else if (num_updates <=20)
    {
    printf("You want to send update of 3 neigh\n");
    //sending update list to server
    FILE *fp = fopen( LIST4,"r");
    struct stat st;
    stat(LIST4,&st);
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
    puts(buffer);
    num_updates++;
    }
    else
    {
    printf("You want to send update of 5 neigh\n");
    //sending update list to server
    FILE *fp = fopen( LIST6,"r");
    struct stat st;
    stat(LIST6,&st);
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
    puts(buffer);
    num_updates++;
    }
    return 1;
}


