#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdbool.h>

#include "../opcode_defines.h"

#define MAGIC_1			'A'
#define MAGIC_2			'L'

typedef struct client
{
	char* username;
	char* password;
	bool hasSession;
	struct sockaddr_in cliaddr;
	int token;
	int messageIdCounter;

	int subscribed_clients_count;
	int followed_clients_count;
	int* subscribed_clients;	// Points to indeces of clients that have subscribed to this one
	int* followed_clients;		// Points to indeces of clients that this one has subscribed to

	int messages_count;
	unsigned char** messages;	// I chose to go the easier route, with more memory usage and less computation and variables
} client;

// Global variables
FILE* log_file;
struct sockaddr_in servaddr, cliaddr;
client* clientArray;
int client_count = 0;

void get_time_stamp(unsigned char* buffer)
{
	// Assume buffer has allocated enough data
	time_t raw_time;
	time(&raw_time);
	struct tm* time = localtime(&raw_time);
	snprintf(buffer, 20, "%02d/%02d/%04d %02d:%02d:%02d", time->tm_mon + 1, time->tm_mday, time->tm_year + 1900, time->tm_hour, time->tm_min, time->tm_sec);
}

void write_log_to_file(const unsigned char* log_str_1, const unsigned char* log_str_2)
{
	unsigned char time_buffer[20];
	unsigned char port_buffer[3];

	get_time_stamp(time_buffer);
	snprintf(port_buffer, 3, "%d", cliaddr.sin_port);
	fputs("<", log_file);
	fputs(time_buffer, log_file);
	fputs("> [", log_file);
	fputs(inet_ntoa(cliaddr.sin_addr), log_file);
	fputs(": ", log_file);
	fputs(port_buffer, log_file);
	fputs("] ", log_file);
	fputs(log_str_1, log_file);
	fputs(log_str_2, log_file);
	fflush(log_file);
}

void get_clients_from_file()
{
	FILE* usernames_passwords = fopen("passwords.txt", "r");
	if(usernames_passwords == NULL)
	{
		printf("The file with the users' info was not found. The program will continue.\n");
		return;
	}

	// Get client count
	for(char c = getc(usernames_passwords); c != EOF; c = getc(usernames_passwords))
		if(c == '\n')
			client_count++;
			

	clientArray = malloc(sizeof(client) * client_count);
	if(clientArray == NULL)
	{
		printf("Not enough memory to store all of the users. The program will continue.\n");
		return;
	}

	rewind(usernames_passwords);	// Reset the file ptr to the beginning
	for(int i = 0; i < client_count; i++)
	{
		char temp_uname[200];
		char temp_pswrd[200];
		fscanf(usernames_passwords, "%s", temp_uname);	// Scan until '\t'
		fscanf(usernames_passwords, "%s", temp_pswrd);	// Scan until '\n'
		clientArray[i].username = malloc(sizeof(char) * strlen(temp_uname) + 1);
		clientArray[i].password = malloc(sizeof(char) * strlen(temp_pswrd) + 1);
		memcpy(clientArray[i].username, temp_uname, strlen(temp_uname) + 1);
		memcpy(clientArray[i].password, temp_pswrd, strlen(temp_pswrd) + 1);

		clientArray[i].hasSession = false;
		clientArray[i].token = 0;
		clientArray[i].messageIdCounter = 0;
		clientArray[i].subscribed_clients_count = 0;
		clientArray[i].followed_clients_count = 0;
		clientArray[i].subscribed_clients = NULL;
		clientArray[i].followed_clients = NULL;
		clientArray[i].messages_count = 0;
	}
	
	for(int i = 0; i < client_count; i++)
	{
		printf("username=%s\n", clientArray[i].username);
		printf("password=%s\n", clientArray[i].password);
		printf("hasSession=%d\n", clientArray[i].hasSession);
	}

	fclose(usernames_passwords);
}

void init_message_header(unsigned char* buffer, unsigned char opcode, int messageLength, int messageID, int token)
{
	buffer[0] = MAGIC_1;
	buffer[1] = MAGIC_2;
	buffer[2] = opcode;
	buffer[3] = messageLength;
	buffer[4] = token >> 24;
	buffer[5] = token >> 16;
	buffer[6] = token >> 8;
	buffer[7] = token;
	buffer[8] = messageID >> 24;
	buffer[9] = messageID >> 16;
	buffer[10] = messageID >> 8;
	buffer[11] = messageID;
}

void print_all_client_connections()
{
	for(int i = 0; i < client_count; i++)
	{
		printf("%s is subscribed to ", clientArray[i].username);
		for(int j = 0; j < clientArray[i].followed_clients_count; j++)
		{
			printf("[ %s ] ", clientArray[clientArray[i].followed_clients[j]].username);
		}
		printf("\n");

		printf("%s is followed by ", clientArray[i].username);
		for(int j = 0; j < clientArray[i].subscribed_clients_count; j++)
		{
			printf("[ %s ] ", clientArray[clientArray[i].subscribed_clients[j]].username);
		}
		printf("\n");
	}
}

void print_all_client_messages()
{
	for(int i = 0; i < client_count; i++)
	{
		printf("Client %s:\n", clientArray[i].username);
		for(int j = 0; j < clientArray[i].messages_count; j++)
		{
			printf("\t[ %s ]\n", clientArray[i].messages[j]);
		}
	}
}

int main()
{
	int ret;
	int sockfd;
	unsigned char recv_buffer[1024];
	unsigned char send_buffer[1024];
	int recv_len;
	socklen_t len;

	unsigned char recent_msg[201];

	get_clients_from_file();
	srand((unsigned)time(NULL));

	log_file = fopen("udp_server.log", "w");

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
	{
		printf("socket() error: %s.\n", strerror(errno));
		return -1;
	}

	// The servaddr is the address and port number that the server will 
	// keep receiving from.
	memset(&servaddr, 0, sizeof(servaddr));
	servaddr.sin_family = AF_INET;
	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
	servaddr.sin_port = htons(32000);
	
	bind(sockfd, (struct sockaddr *) &servaddr, sizeof(servaddr));
	
	while (1)
	{
		len = sizeof(cliaddr);
		recv_len = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *) &cliaddr, &len);
		
		if (recv_len <= 0)
		{
			printf("recvfrom() error: %s.\n", strerror(errno));
			return -1;
		}

		if(recv_buffer[0] == MAGIC_1 && recv_buffer[1] == MAGIC_2)
		{
			int data_length = 0;
			unsigned char opcode = 0;
			int messageID = 0;
			int token = 0;
			unsigned char* log_str_opcode = "";
			unsigned char* log_str_data = "";
			bool user_found = false;
			bool target_client_found = false;
			bool dont_send_message = false;

			switch(recv_buffer[2])
			{
				case OPCODE_LOGIN:
					memset(recent_msg, 0, sizeof(recent_msg));
					memcpy(recent_msg, recv_buffer + 12, recv_buffer[3]);

					printf("Login requested!\n");

					int username_length = (unsigned char*)strchr(recent_msg, '&') - recent_msg;
					char* username = recent_msg;
					char* password = recent_msg + username_length + 1;
					
					for(int i = 0; i < client_count; i++)
					{
						if(strncmp(clientArray[i].username, username, username_length) == 0 && strcmp(clientArray[i].password, password) == 0)
						{
							user_found = true;
							log_str_opcode = "login#";
							log_str_data = "";
							
							clientArray[i].cliaddr = cliaddr;

							clientArray[i].hasSession = true;
							clientArray[i].token = rand();
							clientArray[i].messageIdCounter = 0;
							
							opcode = OPCODE_SUCCESSFUL_LOGIN_ACK;
							messageID = clientArray[i].messageIdCounter;
							token = clientArray[i].token;
							break;	// Exit loop
						}
					}

					if(!user_found)
					{
						opcode = OPCODE_FAILED_LOGIN_ACK;
					}

					break;
				case OPCODE_POST:
					token = recv_buffer[4] << 24 | recv_buffer[5] << 16 | recv_buffer[6] << 8 | recv_buffer[7];

					printf("Trying to post#\n");
					for(int i = 0; i < client_count; i++)
					{
						if(clientArray[i].hasSession && clientArray[i].token == token)
						{
							printf("User found for post#!\n");
							user_found = true;

							memset(recent_msg, 0, sizeof(recent_msg));
							memcpy(recent_msg, recv_buffer + 12, recv_buffer[3]);

							// Go through all of the subscribed clients and add the message to their buffers
							for(int k = 0; k < clientArray[i].subscribed_clients_count; k++)
							{
								int client_index = clientArray[i].subscribed_clients[k];
								// Allocate and copy the memory for the pointer(s)
								unsigned char** tempMessageArrayPointer = malloc(sizeof(char*) * clientArray[client_index].messages_count + 1);
								for(int j = 0; j < clientArray[client_index].messages_count; j++)
								{
									tempMessageArrayPointer[j] = clientArray[client_index].messages[j];
								}
								free(clientArray[client_index].messages);
								clientArray[client_index].messages = tempMessageArrayPointer;

								clientArray[client_index].messages[clientArray[client_index].messages_count] = malloc(sizeof(char) * (strlen(recent_msg) + 1));
								memcpy(clientArray[client_index].messages[clientArray[client_index].messages_count], recent_msg, strlen(recent_msg) + 1);
								clientArray[client_index].messages_count++;
								
								// ACK the poster
								dont_send_message = true;
								log_str_opcode = "post#";
								log_str_data = recent_msg;
								opcode = OPCODE_POST_ACK;
								token = clientArray[i].token;
								write_log_to_file(log_str_opcode, log_str_data);
								init_message_header(send_buffer, opcode, data_length, messageID, token);
								// Send data_length + header_length (data_length + 12) bytes
								ret = sendto(sockfd, send_buffer, data_length + 12, 0, (struct sockaddr*) &cliaddr, len);
								if(ret <= 0)
								{
									printf("sendto() error: %s.\n", strerror(errno));
									return -1;
								}

								// If the subscribed client is online, forward the message
								if(clientArray[client_index].hasSession)
								{
									memset(send_buffer, 0, sizeof(send_buffer));
									send_buffer[12] = '<';
									memcpy(send_buffer + 13, clientArray[i].username, strlen(clientArray[i].username));
									send_buffer[strlen(clientArray[i].username) + 13] = '>';
									memcpy(send_buffer + strlen(clientArray[i].username) + 14, recent_msg, strlen(recent_msg));
									
									log_str_opcode = "forwardto#\n";
									log_str_data = clientArray[client_index].username;
									
									data_length = strlen(recent_msg) + strlen(clientArray[i].username) + 2;
									opcode = OPCODE_FORWARD;
									messageID = clientArray[client_index].messageIdCounter++;
									token = clientArray[client_index].token;

									write_log_to_file(log_str_opcode, log_str_data);

									init_message_header(send_buffer, opcode, data_length, messageID, token);

									// Send data_length + header_length (data_length + 12) bytes
									ret = sendto(sockfd, send_buffer, data_length + 12, 0, (struct sockaddr*) &(clientArray[client_index].cliaddr), len);
									if(ret <= 0)
									{
										printf("sendto() error: %s.\n", strerror(errno));
										return -1;
									}

									// Receive forward ACK from client
									ret = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr*) &(clientArray[client_index].cliaddr), &len);
									if(ret <= 0)
									{
										printf("recvfrom() error: %s.\n", strerror(errno));
										return -1;
									}
									if(recv_buffer[0] == MAGIC_1 && recv_buffer[1] == MAGIC_2 && recv_buffer[2] == OPCODE_FORWARD_ACK)
									{
										printf("forward successful!\n");
									}
									else
									{
										printf("forward got an unrecognized ACK\n");
									}
								}
							}

							log_str_opcode = "post#";
							log_str_data = recent_msg;
							opcode = OPCODE_POST_ACK;
							token = clientArray[i].token;

							break;	// Exit loop
						}
					}

					if(!user_found)
					{
						opcode = OPCODE_MUST_LOGIN_FIRST;
					}

					print_all_client_messages();

					break;
				case OPCODE_RETRIEVE:
					token = recv_buffer[4] << 24 | recv_buffer[5] << 16 | recv_buffer[6] << 8 | recv_buffer[7];

					for(int i = 0; i < client_count; i++)
					{
						if(clientArray[i].hasSession && clientArray[i].token == token)
						{
							user_found = true;

							memset(send_buffer, 0, sizeof(send_buffer));
							memcpy(send_buffer + 12, recent_msg, strlen(recent_msg));
							
							log_str_opcode = "retrieve#\n";
							log_str_data = "";
							
							data_length = strlen(recent_msg);
							opcode = OPCODE_RETRIEVE_ACK;
							messageID = clientArray[i].messageIdCounter++;
							token = clientArray[i].token;

							break;	// Exit loop
						}
					}

					if(!user_found)
					{
						opcode = OPCODE_MUST_LOGIN_FIRST;
					}
					
					break;
				case OPCODE_SUBSCRIBE:
					token = recv_buffer[4] << 24 | recv_buffer[5] << 16 | recv_buffer[6] << 8 | recv_buffer[7];

					for(int i = 0; i < client_count; i++)
					{
						if(clientArray[i].hasSession && clientArray[i].token == token)
						{
							user_found = true;
							printf("Client is valid!\n");

							memset(recent_msg, 0, sizeof(recent_msg));
							memcpy(recent_msg, recv_buffer + 12, recv_buffer[3]);

							printf("The client is asking to subscribe to %s\n", recent_msg);
							
							log_str_opcode = "subscribe#";
							log_str_data = recent_msg;

							token = clientArray[i].token;

							for(int j = 0; j < client_count; j++)
							{
								if(strncmp(clientArray[j].username, recent_msg, (recv_buffer[3] > strlen(clientArray[j].username)) ? recv_buffer[3] : strlen(clientArray[j].username)) == 0)
								{
									printf("Target client found!\n");

									// Below is for follower/subscriber
									clientArray[i].followed_clients_count++;
									// Allocate one size bigger block and copy all of the indeces over (could probably just use realloc)
									int* tempFollowedClientsArray = malloc(sizeof(int) * clientArray[i].followed_clients_count);
									for(int k = 0; k < clientArray[i].followed_clients_count - 1; k++)
									{
										tempFollowedClientsArray[k] = clientArray[i].followed_clients[k];
									}
									free(clientArray[i].followed_clients);
									clientArray[i].followed_clients = tempFollowedClientsArray;
									// Set the last element of followed_clients to point to the index of the followed client
									clientArray[i].followed_clients[clientArray[i].followed_clients_count - 1] = j;

									// Below is for followed/subscribed
									clientArray[j].subscribed_clients_count++;
									// Allocate one size bigger block and copy all of the indeces over (could probably just use realloc)
									int* tempSubscribedClientsArray = malloc(sizeof(int) * clientArray[j].subscribed_clients_count);
									for(int k = 0; k < clientArray[j].subscribed_clients_count - 1; k++)
									{
										tempSubscribedClientsArray[k] = clientArray[j].subscribed_clients[k];
									}
									free(clientArray[j].subscribed_clients);
									clientArray[j].subscribed_clients = tempSubscribedClientsArray;
									// Set the last element of followed_clients to point to the index of the followed client
									clientArray[j].subscribed_clients[clientArray[j].subscribed_clients_count - 1] = i;

									opcode = OPCODE_SUCCESSFUL_SUBSCRIBE_ACK;
									target_client_found = true;
									break;
								}
							}

							if(!target_client_found)
							{
								printf("Target client not found :(\n");
								opcode = OPCODE_FAILED_SUBSCRIBE_ACK;
							}
							print_all_client_connections();

							break;	// Exit loop
						}
					}

					if(!user_found)
					{
						opcode = OPCODE_MUST_LOGIN_FIRST;
					}
					
					break;
				case OPCODE_UNSUBSCRIBE:
					token = recv_buffer[4] << 24 | recv_buffer[5] << 16 | recv_buffer[6] << 8 | recv_buffer[7];

					for(int i = 0; i < client_count; i++)	// Find and validate the client
					{
						if(clientArray[i].hasSession && clientArray[i].token == token)
						{
							user_found = true;
							printf("Client is valid!\n");

							memset(recent_msg, 0, sizeof(recent_msg));
							memcpy(recent_msg, recv_buffer + 12, recv_buffer[3]);

							printf("The client is asking to unsubscribe from %s\n", recent_msg);
							
							log_str_opcode = "unsubscribe#";
							log_str_data = recent_msg;

							token = clientArray[i].token;

							for(int j = 0; j < client_count; j++)	// Find the client from whom to unsubscribe
							{
								if(strncmp(clientArray[j].username, recent_msg, (recv_buffer[3] > strlen(clientArray[j].username)) ? recv_buffer[3] : strlen(clientArray[j].username)) == 0)
								{
									bool is_subscribed = false;
									for(int k = 0; k < clientArray[i].followed_clients_count; k++)
									{
										if(clientArray[i].followed_clients[k] == j)
										{
											is_subscribed = true;
											break;
										}
									}
									if(!is_subscribed)
									{
										target_client_found = false;
										break;
									}
									printf("Unsubscription client found!\n");

									// Below is for follower/subscriber
									clientArray[i].followed_clients_count--;
									
									// Allocate one size smaller block and copy all of the indeces over (except one)
									int* tempFollowedClientsArray = malloc(sizeof(int) * clientArray[i].followed_clients_count);
									int temp_index_counter = 0;
									for(int k = 0; k < clientArray[i].followed_clients_count + 1; k++)	// Include every client
									{
										if(clientArray[i].followed_clients[k] != j)
										{
											tempFollowedClientsArray[temp_index_counter++] = clientArray[i].followed_clients[k];
										}
									}
									free(clientArray[i].followed_clients);
									clientArray[i].followed_clients = tempFollowedClientsArray;
									
									// Below is for followed/subscribed
									clientArray[j].subscribed_clients_count--;
									// Allocate one size smaller block and copy all of the indeces over (except one)
									int* tempSubscribedClientsArray = malloc(sizeof(int) * clientArray[j].subscribed_clients_count);
									temp_index_counter = 0;
									for(int k = 0; k < clientArray[j].subscribed_clients_count + 1; k++)	// Include every client
									{
										if(clientArray[j].subscribed_clients[k] != i)
										{
											tempSubscribedClientsArray[temp_index_counter++] = clientArray[j].subscribed_clients[k];
										}
									}
									free(clientArray[j].subscribed_clients);
									clientArray[j].subscribed_clients = tempSubscribedClientsArray;
									
									opcode = OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK;
									target_client_found = true;
									break;
								}
							}

							if(!target_client_found)
							{
								printf("Target client not found :(\n");
								opcode = OPCODE_FAILED_UNSUBSCRIBE_ACK;
							}
							print_all_client_connections();

							break;	// Exit loop
						}
					}

					if(!user_found)
					{
						opcode = OPCODE_MUST_LOGIN_FIRST;
					}
					
					break;
				default:
					printf("A message was received, but it does not match the expected format.\n");
					break;
			}
			
			if(!dont_send_message)
			{
				write_log_to_file(log_str_opcode, log_str_data);

				init_message_header(send_buffer, opcode, data_length, messageID, token);

				// Send data_length + header_length (data_length + 12) bytes
				ret = sendto(sockfd, send_buffer, data_length + 12, 0, (struct sockaddr*) &cliaddr, len);
				if(ret <= 0)
				{
					printf("sendto() error: %s.\n", strerror(errno));
					return -1;
				}
			}
		}
	}

	return 0;	// This should never execute
}
