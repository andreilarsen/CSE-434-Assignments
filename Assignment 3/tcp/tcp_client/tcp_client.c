#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAGIC_1			'A'
#define MAGIC_2			'L'
#define OPCODE_UPLOAD		(char) 0x80
#define OPCODE_UPLOAD_ACK	(char) 0x81
#define OPCODE_DOWNLOAD		(char) 0x82
#define OPCODE_DOWNLOAD_ACK	(char) 0x83

int main()
{
	int ret;
	int sockfd = 0;
	char user_input[256];
	char header_buffer[8];
	char* filename_buffer;
	char* data_buffer;
	struct sockaddr_in serv_addr;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd < 0) {
		printf("socket() error: %s.\n", strerror(errno));
		return -1;
	}
	
	// Note that this is the server address that the client will connect to.
	// We do not care about the source IP address and port number. 
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	serv_addr.sin_port = htons(31000);
	
	ret = connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if (ret < 0) {
		printf("connect() error: %s.\n", strerror(errno));
		return -1;
	}
	
	while (1)
	{
		fgets(user_input, sizeof(user_input), stdin);
		user_input[strlen(user_input) - 1] = '\0';	// Replace the \n with a \0

		// These two lines allow the client to "gracefully exit" if the
		// user type "exit".
        	
		if (strncmp(user_input, "exit", strlen("exit")) == 0)
			break;
		
		if(strncmp(user_input, "upload$", strlen("upload$")) == 0)
		{
			FILE* file = fopen(user_input + strlen("upload$"), "rb");
			if(file == NULL)
			{
				printf("The file specified could not be found. Please try again.\n");
				continue;
			}
			fseek(file, 0, SEEK_END);
			int file_len = ftell(file);
			rewind(file);
			
			// Fill the header
			header_buffer[0] = MAGIC_1;
			header_buffer[1] = MAGIC_2;
			header_buffer[2] = OPCODE_UPLOAD;
			header_buffer[3] = strlen(user_input + strlen("upload$"));
			header_buffer[4] = file_len >> 24;
			header_buffer[5] = file_len >> 16;
			header_buffer[6] = file_len >> 8;
			header_buffer[7] = file_len;
			
			// Fill the filename
			filename_buffer = malloc(sizeof(char)*strlen(user_input + strlen("upload$")));
			memcpy(filename_buffer, user_input + strlen("upload$"), strlen(user_input + strlen("upload$")));
			
			// Fill the data
			data_buffer = malloc(sizeof(char)*file_len);
			fread(data_buffer, sizeof(char), file_len, file);
			
			send(sockfd, header_buffer, 8, 0);
			send(sockfd, filename_buffer, strlen(user_input + strlen("upload$")), 0);
			send(sockfd, data_buffer, file_len, 0);
			
			// Clean up
			fclose(file);
			free(filename_buffer);
			free(data_buffer);

			// Get the ACK
			recv(sockfd, header_buffer, 8, 0);
			if(header_buffer[0] == MAGIC_1 && header_buffer[1] == MAGIC_2 && header_buffer[2] == OPCODE_UPLOAD_ACK)
			{
				printf("upload_ack$file_upload_successfully!\n");
			}
			else
			{
				//printf("Response received, but is unrecognized.\n");
			}
		}
		else if(strncmp(user_input, "download$", strlen("download$")) == 0)
		{
			// Fill the header
			header_buffer[0] = MAGIC_1;
			header_buffer[1] = MAGIC_2;
			header_buffer[2] = OPCODE_DOWNLOAD;
			header_buffer[3] = strlen(user_input + strlen("download$"));
			
			// Fill the filename
			filename_buffer = malloc(sizeof(char)*strlen(user_input + strlen("download$")) + 1);
			memcpy(filename_buffer, user_input + strlen("download$"), strlen(user_input + strlen("download$")));
			strncpy(filename_buffer + strlen(user_input + strlen("download$")), "", 1);	// Null terminator

			send(sockfd, header_buffer, 4, 0);
			send(sockfd, filename_buffer, strlen(filename_buffer), 0);

			// Get the ACK (assume file exists)
			FILE* file = fopen(filename_buffer, "wb");
			recv(sockfd, header_buffer, 8, 0);
			if(header_buffer[0] == MAGIC_1 && header_buffer[1] == MAGIC_2 && header_buffer[2] == OPCODE_DOWNLOAD_ACK)
			{
				int length = (header_buffer[4] << 24) | (header_buffer[5] << 16) | (header_buffer[6] << 8) | (header_buffer[7]);
				data_buffer = malloc(sizeof(char)*length);
				recv(sockfd, data_buffer, length, 0);
				fwrite(data_buffer, sizeof(char), length, file);
				printf("download_ack$file_download_successfully!\n");

				// Clean up
				free(data_buffer);
			}
			else
			{
				printf("Received something, but it can't be interpreted.\n");
			}
			
			// Clean up
			fclose(file);
			free(filename_buffer);

		}
		else
		{
			printf("The command you typed is not recognized. Available commands are upload$ or download$.\n");
			continue;
		}
	}
	
	close(sockfd);
	
	return 0;
}
