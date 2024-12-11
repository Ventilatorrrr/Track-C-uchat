// api.h
#pragma once

#include "server.h"

// Function Declarations
bool process_login_request(t_client_info *client_info, t_req_type request_type, char *json_string);
char *encrypt_password(const char *password);
char *fetch_client_data(SSL *ssl);
t_req_type identify_request_type(char *json_string);
void *manage_thread(void *arg);
void process_chat_creation(t_client_info *client_info, char *json_string);
void process_message_addition(t_client_info *client_info, char *json_string);
void process_message_deletion(t_client_info *client_info, char *json_string);
void retrieve_user_chats(t_client_info *client_info);
void retrieve_chat_messages(t_client_info *client_info, char *json_string);
void search_users_handler(t_client_info *client_info);
void process_user_registration(t_client_info *client_info, char *json_string);
void process_message_update(t_client_info *client_info, char *json_string);
void update_user_data_handler(t_client_info *client_info, char *json_string);
void record_status_log(char *message, char *value);
void handle_client_request(t_client_info *client_info, t_req_type request_type, char *json_string);
void respond_add_chat(SSL *ssl, t_stat_type status, t_chat *chat_data);
void respond_auth_request(SSL *ssl, t_req_type request_type, t_stat_type status, t_user_data *user_data);
void respond_get_chats(SSL *ssl, t_stat_type status, t_list *chat_list);
void respond_get_messages(SSL *ssl, t_stat_type status, t_list *msg_list);
void respond_user_search(SSL *ssl, t_stat_type status, t_list *user_list);
void respond_message(SSL *ssl, t_req_type request_type, t_stat_type status, t_message_data *message_data);
void respond_status(SSL *ssl, t_req_type request_type, t_stat_type status);

