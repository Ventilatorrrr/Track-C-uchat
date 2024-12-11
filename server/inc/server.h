// server.h
#pragma once

#include "libmx.h"
#include <arpa/inet.h>
#include <cJSON.h>
#include <errno.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

// Macros
#define BACKLOG 4
#define BUF_SIZE 1000000
#define REQUEST_TYPE_COUNT 12
#define STATUS_TYPE_COUNT 5
#define LOG_FILE "server/server.log"
#define SSL_CERTIFICATE "server/resources/ssl/cert.pem"
#define SSL_PRIVATE_KEY "server/resources/ssl/cert-key.pem"

// Enumerations
typedef enum e_loggin_type {
    INFO,
    ERROR,
    JSON_ERROR,
    SSL_ERROR,
    DB_ERROR,
} t_loggin_type;

typedef enum e_stat_type {
    SUCCESS,
    ERROR_JSON,
    ERROR_DB,
    ERROR_INVALID_CREDENTIALS,
    UNKNOWN_STATUS = -1
} t_stat_type;

typedef enum e_req_type {
    REGISTER,
    LOGIN,
    UPDATE_USER,
    GET_USERS_FOR_SEARCH,
    ADD_CHAT,
    GET_CHATS,
    GET_MESSAGES,
    ADD_MESSAGE,
    UPDATE_MESSAGE,
    DELETE_MESSAGE,
    LOGOUT,
    UNKNOWN_REQUEST = -1
} t_req_type;

// Structures
typedef struct s_client_info {
    int client_socket;
    SSL *ssl;
    int id;
    char *username;
} t_client_info;

typedef struct s_user_data {
    int id;
    char *username;
    char *password;
    time_t created_at;
    time_t updated_at;
} t_user_data;

typedef struct s_ch_us_data {
    int id;
    time_t created_at;
} t_ch_us_data;

typedef struct s_chat {
    int id;
    char *title;
    time_t created_at;
    t_ch_us_data current_user;
    t_ch_us_data invitee_user;
} t_chat;

typedef struct s_message_data {
    int message_id;
    int user_id;
    char *username;
    int chat_id;
    char *body;
    time_t created_at;
    time_t updated_at;
    time_t deleted_at;
} t_message_data;

// External Variables
extern pthread_mutex_t logging_mutex;
extern t_list *user_list;

// Function Declarations
bool ssl_configure_context(SSL_CTX *context);
int network_create_socket(void);
SSL_CTX *ssl_create_context(void);
void network_bind_socket(int server_socket, char *port);
void server_create_daemon(void);
void client_list_cleanup(void);
void network_listen_socket(int server_socket);
void logging_to_file(char *message, t_loggin_type log_type);

