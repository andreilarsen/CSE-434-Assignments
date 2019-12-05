#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>

struct header
{
    char magic1;
    char magic2;
    char opcode;
    char payload_len;

    uint32_t token;
    uint32_t msg_id;
};

// This is a data structure that holds important information on a client
typedef struct client
{
    int index;
	char* client_id;
	char* password;
	int state;
	struct sockaddr_in client_addr;
	uint32_t token;
	int messageIdCounter;
    time_t last_time;

	int subscribed_clients_count;
	int followed_clients_count;
	int* subscribed_clients;	// Points to indeces of clients that have subscribed to this one
	int* followed_clients;		// Points to indeces of clients that this one has subscribed to

	int messages_count;
	unsigned char** messages;	// I chose to go the easier route, with more memory usage and less computation and variables
} client;

// TODO: You may need to add more structures to hold global information such as all registered clients, the list of all posted messages, etc.
// Initially all sessions are in the OFFLINE state.

const int h_size = sizeof(struct header);

int client_count = 0;
client* client_array;

// These are the "magic numbers"
#define MAGIC_1     'A'
#define MAGIC_2     'L'

// These are the constants indicating the states
// CAUTION: These states have nothing to do with the states on the client
#define STATE_OFFLINE          0
#define STATE_ONLINE           1
#define STATE_MSG_FORWARD      2
// Now you can define other states in a similar fashion

// These are the events
// CAUTION: These events have nothing to do with the states on the client
#define EVENT_NET_LOGIN                 80
#define EVENT_NET_POST                  81
#define EVENT_NET_SUBSCRIBE             82
#define EVENT_NET_UNSUBSCRIBE           83
#define EVENT_NET_RETRIEVE              84
#define EVENT_NET_LOGOFF                85
#define EVENT_NET_FORWARD_ACK           86
#define EVENT_NET_RESET                 87
#define EVENT_NET_INVALID               255

// These are the constants indicating the opcodes
// First nibble = 0: two-way
// First nibble = 1: from client
// First nibble = 2: from server
#define OPCODE_SESSION_RESET                0x00
#define OPCODE_MUST_LOGIN_FIRST             0x20
#define OPCODE_LOGIN                        0x10
#define OPCODE_SUCCESSFUL_LOGIN_ACK         0x21
#define OPCODE_FAILED_LOGIN_ACK             0x22
#define OPCODE_SUBSCRIBE                    0x11
#define OPCODE_SUCCESSFUL_SUBSCRIBE_ACK     0x23
#define OPCODE_FAILED_SUBSCRIBE_ACK         0x24
#define OPCODE_UNSUBSCRIBE                  0x12
#define OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK   0x25
#define OPCODE_FAILED_UNSUBSCRIBE_ACK       0x26
#define OPCODE_POST                         0x13
#define OPCODE_POST_ACK                     0x27
#define OPCODE_FORWARD                      0x28
#define OPCODE_FORWARD_ACK                  0x14
#define OPCODE_RETRIEVE                     0x15
#define OPCODE_RETRIEVE_ACK                 0x29
#define OPCODE_END_OF_RETRIEVE_ACK          0x2A
#define OPCODE_LOGOUT                       0x16
#define OPCODE_LOGOUT_ACK                   0x2B


uint32_t extract_token_from_the_received_binary_msg(char* recv_buffer)
{
    return ((struct header*) recv_buffer)->token;
}

client* find_the_session_by_token(uint32_t token)
{
    for(int i = 0; i < client_count; i++)
    {
        client* current_client = client_array + i;
        if(current_client->token == token)
            return current_client;
    }

    return NULL;
}

int parse_the_event_from_the_datagram(char* recv_buffer)
{
    if(recv_buffer[2] == OPCODE_LOGIN)
        return EVENT_NET_LOGIN;
    if(recv_buffer[2] == OPCODE_POST)
        return EVENT_NET_POST;
    if(recv_buffer[2] == OPCODE_SUBSCRIBE)
        return EVENT_NET_SUBSCRIBE;
    if(recv_buffer[2] == OPCODE_UNSUBSCRIBE)
        return EVENT_NET_UNSUBSCRIBE;
    if(recv_buffer[2] == OPCODE_RETRIEVE)
        return EVENT_NET_RETRIEVE;
    if(recv_buffer[2] == OPCODE_LOGOUT)
        return EVENT_NET_LOGOFF;
    if(recv_buffer[2] == OPCODE_FORWARD_ACK)
        return EVENT_NET_FORWARD_ACK;
    if(recv_buffer[2] == OPCODE_SESSION_RESET)
        return EVENT_NET_RESET;

    return EVENT_NET_INVALID;
}

client* check_id_password(char* user_id, char* password)
{
    for(int i = 0; i < client_count; i++)
    {
        client* current_client = client_array + i;
        if(strcmp(current_client->client_id, user_id) == 0
           && strcmp(current_client->password, password) == 0)   // Don't include the '\n'
            return current_client;
    }

    return NULL;
}

void get_clients_from_file()
{
	FILE* usernames_passwords = fopen("passwords.txt", "r");
	if(usernames_passwords == NULL)
	{
		printf("The file with the users' info was not found. The program will continue. Expect undefined behavior.\n");
		return;
	}

	// Get client count
	for(char c = getc(usernames_passwords); c != EOF; c = getc(usernames_passwords))
		if(c == '\n')
			client_count++;
			

	client_array = malloc(sizeof(client) * client_count);
	if(client_array == NULL)
	{
		printf("Not enough memory to store all of the users. The program will continue. Expect undefined behavior.\n");
		return;
	}

	rewind(usernames_passwords);	// Reset the file ptr to the beginning
	for(int i = 0; i < client_count; i++)
	{
		char temp_uname[200];
		char temp_pswrd[200];
		fscanf(usernames_passwords, "%s", temp_uname);	// Scan until '\t'
		fscanf(usernames_passwords, "%s", temp_pswrd);	// Scan until '\n'
		client_array[i].client_id = malloc(sizeof(char) * strlen(temp_uname) + 1);
		client_array[i].password = malloc(sizeof(char) * strlen(temp_pswrd) + 1);
		memcpy(client_array[i].client_id, temp_uname, strlen(temp_uname) + 1);
		memcpy(client_array[i].password, temp_pswrd, strlen(temp_pswrd) + 1);

        client_array[i].index = i;
		client_array[i].state = STATE_OFFLINE;
		client_array[i].token = 0;
		client_array[i].messageIdCounter = 0;
        client_array[i].last_time = time(NULL);
		client_array[i].subscribed_clients_count = 0;
		client_array[i].followed_clients_count = 0;
		client_array[i].subscribed_clients = NULL;
		client_array[i].followed_clients = NULL;
		client_array[i].messages_count = 0;
	}

	fclose(usernames_passwords);
}


int main(int argc, char* argv[])
{
    int sockfd;
    struct sockaddr_in serv_addr, cli_addr;
    char send_buffer[1024];
    char recv_buffer[1024];
    int recv_len;
    socklen_t len;

    // Now you need to load all users' information and fill this array.
    // Optionally, you can just hardcode each user.

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0)
    {
        printf("socket() error: %s.\n", strerror(errno));
        return -1;
    }

    // The servaddr is the address and port number that the server will keep receiving from.
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(32000);

    int ret = bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));

    if (ret < 0)
    {
        printf("bind error!\n");
        return -1;
    }

    struct header *ph_send = (struct header *)send_buffer;
    struct header *ph_recv = (struct header *)recv_buffer;

    // Read the clients from the file
    get_clients_from_file();

    // Init the random seed for the token
    srand((unsigned) time(NULL));

    while (1)
    {
        // Note that the program will still block on recvfrom()
        // You may call select() only on this socket file descriptor with
        // a timeout, or set a timeout using the socket options.

        len = sizeof(cli_addr);
        // Clear out the buffers, it helps to not add null terminators everywhere later
        memset(recv_buffer, 0, sizeof(recv_buffer));
        memset(send_buffer, 0, sizeof(recv_buffer));
        // recv_len(socket file descriptor, receive buffer, number of bytes to be received, flags, client address, length of client address structure);
        recv_len = recvfrom(sockfd, recv_buffer, sizeof(recv_buffer), 0, (struct sockaddr *) &cli_addr, &len);

        if (recv_len <= 0)
        {
            printf("recvfrom() error: %s.\n", strerror(errno));
            return -1;
        }

        // Now we know there is an event from the network
        // TODO: Figure out which event and process it according to the
        // current state of the session referred.
        uint32_t token = ph_recv->token;
        client* current_client = find_the_session_by_token(token);
        int event = parse_the_event_from_the_datagram(recv_buffer);

        // Record the last time that this session is active.
        if(current_client != NULL)
            current_client->last_time = time(NULL);
        
        // For a login message, the current_client should be NULL and
        // the token is 0. For other messages, they should be valid.
        if (event == EVENT_NET_LOGIN)
        {
            char* id_password = recv_buffer + h_size;

            char* delimiter = strchr(id_password, '&');
            char* password = delimiter + 1;
            *delimiter = 0; // Add a null terminator
            // Note that this null terminator can break the user ID
            // and the password without allocating other buffers.
            char* user_id = id_password;

            delimiter = strchr(password, '\n');
            *delimiter = 0; // Add a null terminator
            // Note that since we did not process it on the client side,
            // and since it is always typed by a user, there must be a
            // trailing new line. We just write a null terminator on this
            // place to terminate the password string.

            // The server need to reply a msg anyway, and this reply msg
            // contains only the header
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;

            current_client = check_id_password(user_id, password);
            if (current_client != NULL)  // This means the login is successful.
            {
                ph_send->opcode = OPCODE_SUCCESSFUL_LOGIN_ACK;
                ph_send->token = rand();

                current_client->state = STATE_ONLINE;
                current_client->token = ph_send->token;
                current_client->last_time = time(NULL);
                current_client->client_addr = cli_addr;
            }
            else
            {
                ph_send->opcode = OPCODE_FAILED_LOGIN_ACK;
                ph_send->token = 0;
            }

            sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr));
        }
        else if (event == EVENT_NET_POST)
        {
            if(current_client != NULL && current_client->state == STATE_ONLINE)
            {
                for(int i = 0; i < current_client->subscribed_clients_count; i++)
                {
                    client* target = client_array + current_client->subscribed_clients[i];
                    char* text = recv_buffer + h_size;
                    char* payload = send_buffer + h_size;

                    // This formatting the "<client_a>some_text" in the payload
                    // of the forward msg, and hence, the client does not need
                    // to format it, i.e., the client can just print it out.
                    snprintf(payload, sizeof(send_buffer) - h_size, "<%s>%s", current_client->client_id, text);

                    int m = strlen(payload) + 1;    // Include the null terminator

                    // Allocate and copy the memory for the pointer(s)
                    unsigned char** tempMessageArrayPointer = malloc(sizeof(char*) * target->messages_count + 1);
                    for(int j = 0; j < target->messages_count; j++)
                    {
                        tempMessageArrayPointer[j] = target->messages[j];
                    }
                    free(target->messages);
                    target->messages = tempMessageArrayPointer;
                    // Add the new message
                    target->messages[target->messages_count] = calloc(m + 1, sizeof(char));  // Include null terminator, calloc (not malloc) for same reason
                    memcpy(target->messages[target->messages_count], payload, m);
                    target->messages_count++;

                    // Only send if the subscriber is online, otherwise it can request the messages later
                    if(target->state != STATE_OFFLINE)
                    {
                        // "target" is the session structure of the target client.
                        target->state = STATE_MSG_FORWARD;

                        ph_send->magic1 = MAGIC_1;
                        ph_send->magic2 = MAGIC_2;
                        ph_send->opcode = OPCODE_FORWARD;
                        ph_send->payload_len = m;
                        ph_send->msg_id = 0; // Note that I didn't use msg_id here.

                        sendto(sockfd, send_buffer, h_size + m, 0, (struct sockaddr *) &target->client_addr, sizeof(target->client_addr));
                    }
                }
            }
            // Send back the post ack to this publisher.
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->opcode = OPCODE_POST_ACK;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0; // Note that I didn't use msg_id here.
            
            sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr*) &current_client->client_addr, sizeof(current_client->client_addr));
        }
        else if (event == EVENT_NET_SUBSCRIBE)
        {
            // The server need to reply a msg anyway, and this reply msg
            // contains only the header
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;

            if(current_client != NULL && current_client->state == STATE_ONLINE)
            {
                int subscribe_target_found = 0;
                // Go through all of the clients
                for(int i = 0; i < client_count; i++)
                {
                    client* target = client_array + i;
                    char* text = recv_buffer + h_size;
                    char* payload = send_buffer + h_size;

                    // Find the client with the same client_id
                    if(strncmp(target->client_id, text, strlen(target->client_id)) == 0)
                    {
                        subscribe_target_found = 1;

                        // Below is for follower/subscriber
                        current_client->followed_clients_count++;
                        // Allocate one size bigger block and copy all of the indeces over (could probably just use realloc)
                        int* tempFollowedClientsArray = malloc(sizeof(int) * current_client->followed_clients_count);
                        for(int k = 0; k < current_client->followed_clients_count - 1; k++)
                        {
                            tempFollowedClientsArray[k] = current_client->followed_clients[k];
                        }
                        free(current_client->followed_clients);
                        current_client->followed_clients = tempFollowedClientsArray;
                        // Set the last element of followed_clients to point to the index of the followed client
                        current_client->followed_clients[current_client->followed_clients_count - 1] = target->index;

                        // Below is for followed/subscribed
                        target->subscribed_clients_count++;
                        // Allocate one size bigger block and copy all of the indeces over (could probably just use realloc)
                        int* tempSubscribedClientsArray = malloc(sizeof(int) * target->subscribed_clients_count);
                        for(int k = 0; k < target->subscribed_clients_count - 1; k++)
                        {
                            tempSubscribedClientsArray[k] = target->subscribed_clients[k];
                        }
                        free(target->subscribed_clients);
                        target->subscribed_clients = tempSubscribedClientsArray;
                        // Set the last element of followed_clients to point to the index of the followed client
                        target->subscribed_clients[target->subscribed_clients_count - 1] = current_client->index;

                        ph_send->opcode = OPCODE_SUCCESSFUL_SUBSCRIBE_ACK;
                        break;  // Stop going through all of the clients
                    }
                }

                // If no subscription client is found
                if(subscribe_target_found <= 0)
                {
                    ph_send->opcode = OPCODE_FAILED_SUBSCRIBE_ACK;
                }
            }
            else    // Current client doesn't exist or isn't online
            {
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST;
            }

            sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr));
        }
        else if (event == EVENT_NET_UNSUBSCRIBE)
        {
            // The server need to reply a msg anyway, and this reply msg
            // contains only the header
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;

            if(current_client != NULL && current_client->state == STATE_ONLINE)
            {
                int unsubscribe_target_found = 0;
                // Go through all of the followed clients
                for(int i = 0; i < current_client->followed_clients_count; i++)
                {
                    client* target = client_array + current_client->followed_clients[i];
                    char* text = recv_buffer + h_size;
                    char* payload = send_buffer + h_size;

                    // Find the client with the same client_id
                    if(strncmp(target->client_id, text, strlen(target->client_id)) == 0)
                    {
                        unsubscribe_target_found = 1;

                        // Below is for follower/subscriber
                        current_client->followed_clients_count--;
                        
                        // Allocate one size smaller block and copy all of the indeces over (except one)
                        int* tempFollowedClientsArray = malloc(sizeof(int) * current_client->followed_clients_count);
                        int temp_index_counter = 0;
                        for(int k = 0; k < current_client->followed_clients_count + 1; k++)	// Include every client
                        {
                            if(current_client->followed_clients[k] != target->index)
                            {
                                tempFollowedClientsArray[temp_index_counter++] = current_client->followed_clients[k];
                            }
                        }
                        free(current_client->followed_clients);
                        current_client->followed_clients = tempFollowedClientsArray;

                        // Below is for followed/subscribed
                        target->subscribed_clients_count--;
                        // Allocate one size smaller block and copy all of the indeces over (except one)
                        int* tempSubscribedClientsArray = malloc(sizeof(int) * target->subscribed_clients_count);
                        temp_index_counter = 0;
                        for(int k = 0; k < target->subscribed_clients_count + 1; k++)	// Include every client
                        {
                            if(target->subscribed_clients[k] != current_client->index)
                            {
                                tempSubscribedClientsArray[temp_index_counter++] = target->subscribed_clients[k];
                            }
                        }
                        free(target->subscribed_clients);
                        target->subscribed_clients = tempSubscribedClientsArray;

                        ph_send->opcode = OPCODE_SUCCESSFUL_UNSUBSCRIBE_ACK;
                        break;  // Stop going through all of the clients
                    }
                }

                // If no subscription client is found
                if(unsubscribe_target_found <= 0)
                {
                    ph_send->opcode = OPCODE_FAILED_UNSUBSCRIBE_ACK;
                }
                
            }
            else    // Current client doesn't exist or isn't online
            {
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST;
            }

            sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr));
        }
        else if (event == EVENT_NET_RETRIEVE)
        {
            // The server need to reply a msg anyway
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->msg_id = 0;

            if(current_client != NULL && current_client->state == STATE_ONLINE)
            {
                int n = atoi(recv_buffer + h_size);
                if(n == 0)  // Client asks for 0 messages or not an integer
                    break;  // Jump to sending the END_OF_RETRIEVE_ACK

                // Send the messages
                int i = current_client->messages_count - n;
                if(i < 0)
                    i = 0;
                for(; i < current_client->messages_count; i++)
                {
                    char* payload = send_buffer + h_size;

                    int m = strlen(current_client->messages[i]);

                    ph_send->opcode = OPCODE_RETRIEVE_ACK;
                    ph_send->payload_len = m;
                    memcpy(payload, current_client->messages[i], strlen(current_client->messages[i]));

                    sendto(sockfd, send_buffer, h_size + m, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr));
                }

                // Prepare to send the END_OF_RETRIEVE_ACK
                ph_send->opcode = OPCODE_END_OF_RETRIEVE_ACK;
                ph_send->payload_len = 0;
                
            }
            else    // Current client doesn't exist or isn't online
            {
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST;
            }

            sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr));
        }
        else if (event == EVENT_NET_LOGOFF)
        {
            // The server need to reply a msg anyway
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;

            if(current_client != NULL && current_client->state == STATE_ONLINE)
            {
                ph_send->opcode = OPCODE_LOGOUT_ACK;
                current_client->state = STATE_OFFLINE;
            }
            else    // Current client doesn't exist or isn't online
            {
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST;
            }

            sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr));
        }
        else if (event == EVENT_NET_FORWARD_ACK)
        {
            if(current_client != NULL && current_client->state != STATE_OFFLINE)
            {
                // No need to respond, this is an ACK
                current_client->state = STATE_ONLINE;
            }
            else    // Current client doesn't exist or isn't online
            {
                ph_send->magic1 = MAGIC_1;
                ph_send->magic2 = MAGIC_2;
                ph_send->opcode = OPCODE_MUST_LOGIN_FIRST;
                ph_send->payload_len = 0;
                ph_send->msg_id = 0;

                sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr));
            }
        }
        else if (event == EVENT_NET_RESET)
        {
            if(current_client != NULL)
            {
                printf("SESSION RESET BY CLIENT\n");
                // No need to respond
                current_client->state = STATE_OFFLINE;
            }
        }
        else  // if (event == EVENT_NET_INVALID)
        {
            // Reset the connection
            ph_send->magic1 = MAGIC_1;
            ph_send->magic2 = MAGIC_2;
            ph_send->opcode = OPCODE_SESSION_RESET;
            ph_send->payload_len = 0;
            ph_send->msg_id = 0;

            if(current_client != NULL)
            {
                current_client->state = STATE_OFFLINE;
            }

            sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &cli_addr, sizeof(cli_addr));
        }

        printf("Checking timeouts...\n");
        time_t current_time = time(NULL);

        for(int i = 0; i < client_count; i++)
        {
            client* temp_client = client_array + i;
            if(temp_client != NULL && temp_client->state != STATE_OFFLINE)
            {
                int diff = difftime(current_time, temp_client->last_time);
                printf("Client %s time:%d\n", temp_client->client_id, diff);
                if(diff > 60)
                {
                    printf("Resetting connection.\n");

                    // Reset the connection
                    ph_send->magic1 = MAGIC_1;
                    ph_send->magic2 = MAGIC_2;
                    ph_send->opcode = OPCODE_SESSION_RESET;
                    ph_send->payload_len = 0;
                    ph_send->msg_id = 0;

                    sendto(sockfd, send_buffer, h_size, 0, (struct sockaddr *) &(temp_client->client_addr), sizeof(cli_addr));

                    temp_client->state = STATE_OFFLINE;
                }
                else
                {
                    printf("Connection intact.\n");
                }
                
            }
        }

    } // This is the end of the while loop

    return 0;   // This should never execute
} // This is the end of main()