#ifndef UDP_SERVER_H
#define UDP_SERVER_H

typedef struct Client
{
    char* username;
    char* password;
} Client;

typedef struct Message
{
    int length;
    char* header;
    char* data;
}

#endif // UDP_SERVER_H