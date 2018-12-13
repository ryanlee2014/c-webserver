#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include "Disk.h"
#include "File.h"
unsigned long get_file_size(const char *path)

{

    unsigned long filesize = -1;

    struct stat statbuff;

    if(stat(path,&statbuff)<0)

    return filesize;

    else

    filesize = statbuff.st_size;

    return filesize;

}
char content[1000000];
char file_buffer[1000000];
void init_file()
{
    initSystem();
    initRootDir();
    //const char* dir = "/home/ryan/webtestpage/Crawler4jDate";
    int file_name = 1000;
    char buffer[1024];

    for(int i = 0;i <= 10; ++i) {
        sprintf(buffer,"/Users/ryan/file-system/simpleFS/%d.html",file_name + i);
        int size = get_file_size(buffer);
        printf("size:  %d\n",size);
        
        int file_id = open(buffer, O_RDONLY);
        printf("file_id : %d\n",file_id);
        sprintf(buffer,"%d.html",file_name + i);
        printf("Buffer_name: %s\n",buffer);
        creatFile(buffer, size);
        //int ret = 0;
        puts("Created file");
        read(file_id, file_buffer,size);
        puts("Readed file");
        //printf("%s\n",file_buffer);
        my_write(buffer,file_buffer);
        printf("name:%s, content:%s\n",buffer, file_buffer);
        puts("Writed file");
        //while((ret = read(file_id,file_buffer,size)) > 0) {
        //}
        //my_write(buffer, )
        printf("Here%d\n",i);
        //sleep(1);
    }
    puts("Out");
    for(int i = 0; i <=10; ++i) {
        puts("Come here");
        //sprintf(buffer,"%s/%d.html",dir,file_name + i);
        sprintf(buffer,"%d.html",file_name + i);
        printf("file_name: %s\n",buffer);
        
        my_read(buffer,0,content);
        //res[4] = 0;
        printf("get:%d %s\n",file_name + i, content);
    }
}

int main()
{
    init_file();
}