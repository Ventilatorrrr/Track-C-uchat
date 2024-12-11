// database.h
#pragma once

#include "server.h"
#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>

#define DATABASE_FILE "server/src/database/uchat.db"

// Database Function Declarations
bool database_add_user(t_user_data *user_data);
bool database_update_user(t_user_data *user_data);
char *database_fetch_username(int user_id);
sqlite3 *database_connect(void);
t_chat *database_add_chat_entry(t_chat *chat_data);
t_list *database_fetch_chat_messages(int chat_id);
t_list *database_fetch_user_chats(int current_user_id);
t_list *database_fetch_user_list(int current_user_id);
t_message_data *database_add_message_entry(t_message_data *msg_data);
t_message_data *database_remove_message(t_message_data *msg_data);
t_message_data *database_modify_message(t_message_data *msg_data);
t_user_data *database_fetch_user_data(char *username);
void database_disconnect(sqlite3 *db);
void database_log_error(char *message, sqlite3 *db);


