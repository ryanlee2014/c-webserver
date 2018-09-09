//
// Created by Ryan on 2018/9/8.
//

#ifndef WEBSERVER_STATIC_CONST_H
#define WEBSERVER_STATIC_CONST_H

struct {
    char *ext;
    char *filetype;
} extensions[] = {
        {"gif",  "image/gif"},
        {"jpg",  "image/jpg"},
        {"jpeg", "image/jpeg"},
        {"png",  "image/png"},
        {"ico",  "image/ico"},
        {"zip",  "image/zip"},
        {"gz",   "image/gz"},
        {"tar",  "image/tar"},
        {"htm",  "text/html"},
        {"html", "text/html"},
        {"js",   "application/javascript"},
        {"css",  "text/css"},
        {0,      0}};

unsigned ip_to_num(std::string ip) {
    unsigned offset = 1u << 24;
    unsigned ipaddr = 0;
    char buf[BUFSIZE];
    for(int i = 0;i<ip.length();++i)buf[i] = ip[i];
    buf[ip.length()] = 0;
    auto pos = 0;
    while(buf[pos])
    {
        unsigned tmp = 0;
        while(isdigit(buf[pos])) {
            tmp *= 10;
            tmp += buf[pos++] - '0';
        }
        ipaddr += tmp * offset;
        offset >>= 8;
        ++pos;
    }
    return ipaddr;
}

long get_file_size(const char *filename) {
    struct stat f_stat{};

    if (stat(filename, &f_stat) == -1) {
        return 0;
    }
    return (long) f_stat.st_size;
}

void valid_check(int argc, char **argv) {
    int i;
    if (argc < 3 || argc > 3 || !strcmp(argv[1], "-?")) {
        (void) printf("hint: nweb Port-Number Top-Directory\t\tversion %d\n\n"
                      "\tnweb is a small and very safe mini web server\n"
                      "\tnweb only servers out file/web pages with extensions named below\n"
                      "\t and only from the named directory or its sub-directories.\n"
                      "\tThere is no fancy features = safe and secure.\n\n"
                      "\tExample: nweb 8181 /home/nwebdir &\n\n"
                      "\tOnly Supports:", VERSION);
        for (i = 0; extensions[i].ext != 0; ++i)
            (void) printf(" %s", extensions[i].ext);

        (void) printf("\n\tNot Supported: URLs including \"..\", Java, Javascript, CGI\n"
                      "\tNot Supported: directories / /etc /bin /lib /tmp /usr /dev /sbin \n"
                      "\tNo warranty given or implied\n\tNigel Griffiths nag@uk.ibm.com\n");
        exit(0);
    }
    if (!strncmp(argv[2], "/", 2) || !strncmp(argv[2], "/etc", 5) ||
        !strncmp(argv[2], "/bin", 5) || !strncmp(argv[2], "/lib", 5) ||
        !strncmp(argv[2], "/tmp", 5) || !strncmp(argv[2], "/usr", 5) ||
        !strncmp(argv[2], "/dev", 5) || !strncmp(argv[2], "/sbin", 6)) {
        (void) printf("ERROR: Bad top directory %s, see nweb -?\n", argv[2]);
        exit(3);
    }
    if (chdir(argv[2]) == -1) {
        (void) printf("ERROR: Can't Change to directory %s\n", argv[2]);
        exit(4);
    }
}


#endif //WEBSERVER_STATIC_CONST_H
