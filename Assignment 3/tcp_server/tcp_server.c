#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// This line must be included if you want to use multithreading.
// Besides, use "gcc ./tcp_receive.c -lpthread -o tcp_receive" to compile
// your code. "-lpthread" means link against the pthread library.
#include <pthread.h>

// This the "main" function of each worker thread. All worker thread runs
// the same function. This function must take only one argument of type 
// "void *" and return a value of type "void *".

#define MAGIC_1			'A'
#define MAGIC_2			'L'
#define OPCODE_UPLOAD		(char) 0x80
#define OPCODE_UPLOAD_ACK	(char) 0x81
#define OPCODE_DOWNLOAD		(char) 0x82
#define OPCODE_DOWNLOAD_ACK	(char) 0x83

void *worker_thread(void *arg)
{
	int ret;
	int connfd = (int)(long)arg;
	char header_buffer[8];
	char* filename_buffer;
	char* data_buffer;
	
	printf("[%d] worker thread started.\n", connfd);
	
	while(1)
	{
		ret = recv(connfd, header_buffer, 8, 0);
		
		if(ret < 0)
		{
			// Input / output error.
			printf("[%d] recv() error: %s.\n", connfd, strerror(errno));
			return NULL;
		}
		else if (ret == 0)
		{
			// The connection is terminated by the other end.
			printf("[%d] connection lost\n", connfd);
			break;
		}

		if(header_buffer[0] == MAGIC_1 && header_buffer[1] == MAGIC_2 && header_buffer[2] == OPCODE_UPLOAD)
		{
			int length = (header_buffer[4] << 24) | (header_buffer[5] << 16) | (header_buffer[6] << 8) | (header_buffer[7]);
			filename_buffer = malloc(sizeof(char)*header_buffer[3] + 1);
			data_buffer = malloc(sizeof(char)*length);

			ret = recv(connfd, filename_buffer, header_buffer[3], 0);			// Get the filename
			strncpy(filename_buffer + header_buffer[3], "", 1);			// null terminator
			printf("The filename is %s\n", filename_buffer);
			
			FILE* file = fopen(filename_buffer, "wb");
			ret = recv(connfd, data_buffer, length, 0);	// Get the file bytes
			printf("Received %d bytes.\n", ret);
			fwrite(data_buffer, sizeof(char), length, file);
			printf("Wrote %d bytes.\n", length);
			
			// Clean up
			fclose(file);
			free(filename_buffer);
			free(data_buffer);

			// Prepare header and send ACK
			header_buffer[2] = OPCODE_UPLOAD_ACK;
			ret = send(connfd, header_buffer, 8, 0);
		}
		else if(header_buffer[0] == MAGIC_1 && header_buffer[1] == MAGIC_2 && header_buffer[2] == OPCODE_DOWNLOAD)
		{
			// Assume file exists and nothing goes wrong
			filename_buffer = malloc(sizeof(char)*header_buffer[3] + 1);
			strncpy(filename_buffer, header_buffer + 4, 4);

			ret = recv(connfd, filename_buffer + 4, header_buffer[3] - 4, 0);
			strncpy(filename_buffer + header_buffer[3], "", 1);	// Null terminator
			FILE* file = fopen(filename_buffer, "rb");
			fseek(file, 0, SEEK_END);
			int file_len = ftell(file);
			rewind(file);

			// Fill the header
			header_buffer[0] = MAGIC_1;
			header_buffer[1] = MAGIC_2;
			header_buffer[2] = OPCODE_DOWNLOAD_ACK;
			header_buffer[3] = strlen(filename_buffer);
			header_buffer[4] = file_len >> 24;
			header_buffer[5] = file_len >> 16;
			header_buffer[6] = file_len >> 8;
			header_buffer[7] = file_len;

			// No need to send the filename, the client knows it already
			data_buffer = malloc(sizeof(char)*file_len);
			fread(data_buffer, sizeof(char), file_len, file);

			send(connfd, header_buffer, 8, 0);
			send(connfd, data_buffer, file_len, 0);

			// Clean up
			fclose(file);
			free(filename_buffer);
			free(data_buffer);
		}
		else
		{
			printf("Something was received, but it is wierd.\n");
		}
		
		// TODO: Process your message, receive chunks of the byte stream, 
		// write the chunks to a file. You also need an inner loop to 
		// receive and write each chunk.
	}
	
	printf("[%d] worker thread terminated.\n", connfd);
}

// The main thread, which only accepts new connections. Connection socket
// is handled by the worker thread.
int main()
{
	int ret;
	socklen_t len;
	int listenfd = 0, connfd = 0;
	struct sockaddr_in serv_addr;
	struct sockaddr_in client_addr;
	
	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if(listenfd < 0)
	{
		printf("socket() error: %s.\n", strerror(errno));
		return -1;
	}
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	serv_addr.sin_port = htons(31000);
	
	ret = bind(listenfd, (struct sockaddr*) &serv_addr, sizeof(serv_addr));
	if(ret < 0)
	{
		printf("bind() error: %s.\n", strerror(errno));
		return -1;
	}
	
	if(listen(listenfd, 10) < 0)
	{
		printf("listen() error: %s.\n", strerror(errno));
		return -1;
	}
	
	while(1)
	{
		printf("waiting for connection...\n");
		connfd = accept(listenfd, (struct sockaddr*) &client_addr, &len);
		
		if(connfd < 0)
		{
			printf("accept() error: %s.\n", strerror(errno));
			return -1;
		}
		printf("conn accept - %s.\n", inet_ntoa(client_addr.sin_addr));
		
		pthread_t tid;
		pthread_create(&tid, NULL, worker_thread, (void *)(long)connfd);
    }
    return 0;
}
