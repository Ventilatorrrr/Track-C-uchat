#include "api.h"
#include "database.h"

void handle_client_request(t_client_info *client_info, t_req_type request_type, char *json_string) {
    switch (request_type) {
        case REGISTER:
            process_user_registration(client_info, json_string);
            break;
        case LOGIN:
            process_login_request(client_info, LOGIN, json_string);
            break;
        case UPDATE_USER:
            update_user_data_handler(client_info, json_string);
            break;
        case GET_USERS_FOR_SEARCH:
            search_users_handler(client_info);
            break;
        case ADD_CHAT:
            process_chat_creation(client_info, json_string);
            break;
        case GET_CHATS:
            retrieve_user_chats(client_info);
            break;
        case GET_MESSAGES:
            retrieve_chat_messages(client_info, json_string);
            break;
        case ADD_MESSAGE:
            process_message_addition(client_info, json_string);
            break;
        case UPDATE_MESSAGE:
            process_message_update(client_info, json_string);
            break;
        case DELETE_MESSAGE:
            process_message_deletion(client_info, json_string);
            break;
        case UNKNOWN_REQUEST:
            logging_to_file("Could not process a client request. A non-existent request type was received", ERROR);
            break;
        default:
            break;
    }

    return;
}

void record_status_log(char *message, char *value) {
    char *main_message = (char *) malloc(200 * sizeof(char));
    char *data = (char *) malloc(100 * sizeof(char));
    *main_message = '\0';
    sprintf(data, ": %s", value);
    strcat(main_message, message);
    strcat(main_message, data);
    logging_to_file(main_message, INFO);
    free(data);
    free(main_message);
}

char *encrypt_password(const char *password) {
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    const EVP_MD *md = EVP_get_digestbyname("SHA256");

    EVP_DigestInit(ctx, md);
    EVP_DigestUpdate(ctx, password, strlen(password));
    EVP_DigestFinal(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);
    char *output = malloc(sizeof(char) * 64);

    for (unsigned int i = 0; i < hash_len; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }

    return output;
}

void process_user_registration(t_client_info *client_info, char *json_string) {
    t_req_type request_type = REGISTER;
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        return;
    }

    const cJSON *json_data_obj = cJSON_GetObjectItemCaseSensitive(json, "data");
    t_user_data *user_data = (t_user_data *)malloc(sizeof(t_user_data));

    if (cJSON_IsObject(json_data_obj)) {
        const cJSON *json_username = cJSON_GetObjectItemCaseSensitive(json_data_obj, "username");
        const cJSON *json_password = cJSON_GetObjectItemCaseSensitive(json_data_obj, "password");

        if (cJSON_IsString(json_username) && cJSON_IsString(json_password)) {
            user_data->username = mx_strdup((const char *)json_username->valuestring);
            user_data->password = encrypt_password((const char *) mx_strdup((const char *) json_password->valuestring));
        } else {
            logging_to_file("Could not parse the \"data\" fields from a cJSON object", JSON_ERROR);
            respond_status(client_info->ssl, request_type, ERROR_JSON);
            free(user_data);
            cJSON_Delete(json);
            return;
        }
    } else {
        logging_to_file("Could not parse the \"data\" object from a cJSON object", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        free(user_data);
        cJSON_Delete(json);
        return;
    }

    user_data->created_at = time(NULL);

    if (!database_add_user(user_data)) {
        logging_to_file("Could not post user data to database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        free(user_data);
        cJSON_Delete(json);
        return;
    }

    t_user_data *new_user_data = database_fetch_user_data(user_data->username);

    if (!new_user_data) {
        logging_to_file("Could not get user data from the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        free(user_data);
        cJSON_Delete(json);
        return;
    }

    client_info->id = new_user_data->id;
    client_info->username = mx_strdup((const char *)new_user_data->username);

    respond_auth_request(client_info->ssl, request_type, SUCCESS, new_user_data);
    free(user_data);
    free(new_user_data);
    cJSON_Delete(json);
    return;
}

bool process_login_request(t_client_info *client_info, t_req_type request_type, char *json_string) {
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        return false;
    }

    const cJSON *json_credentials_obj = cJSON_GetObjectItemCaseSensitive(json, "credentials");
    t_user_data *user_data = (t_user_data *)malloc(sizeof(t_user_data));

    if (cJSON_IsObject(json_credentials_obj)) {
        const cJSON *json_username = cJSON_GetObjectItemCaseSensitive(json_credentials_obj, "username");
        const cJSON *json_password = cJSON_GetObjectItemCaseSensitive(json_credentials_obj, "password");

        if (cJSON_IsString(json_username) && cJSON_IsString(json_password)) {
            user_data->username = mx_strdup((const char *) json_username->valuestring);
            user_data->password = mx_strdup((const char *) encrypt_password((const char *) json_password->valuestring));
        } else {
            logging_to_file("Could not parse the \"credentials\" fields from a cJSON object", JSON_ERROR);
            respond_status(client_info->ssl, request_type, ERROR_JSON);
            free(user_data);
            cJSON_Delete(json);
            return false;
        }
    } else {
        logging_to_file("Could not parse the \"credentials\" object from a cJSON object", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        free(user_data);
        cJSON_Delete(json);
        return false;
    }

    t_user_data *new_user_data = database_fetch_user_data(user_data->username);

    if (!new_user_data) {
        logging_to_file("The passed user's credentials is invalid", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_INVALID_CREDENTIALS);
        free(user_data);
        cJSON_Delete(json);
        return false;
    }

    client_info->id = new_user_data->id;
    client_info->username = mx_strdup((const char *) new_user_data->username);

    if (mx_strcmp(new_user_data->password, user_data->password) != 0) {
        logging_to_file("The passed user's credentials is invalid", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_INVALID_CREDENTIALS);
        free(user_data);
        free(new_user_data);
        cJSON_Delete(json);
        return false;
    }

    if (request_type == LOGIN) {
        respond_auth_request(client_info->ssl, request_type, SUCCESS, new_user_data);
    }

    free(user_data);
    free(new_user_data);
    cJSON_Delete(json);
    return true;
}

void update_user_data_handler(t_client_info *client_info, char *json_string) {
    t_req_type request_type = UPDATE_USER;
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        return;
    }

    const cJSON *json_data_obj = cJSON_GetObjectItemCaseSensitive(json, "data");
    t_user_data *user_data = (t_user_data *)malloc(sizeof(t_user_data));

    if (cJSON_IsObject(json_data_obj)) {
        const cJSON *json_password = cJSON_GetObjectItemCaseSensitive(json_data_obj, "password");

        if (cJSON_IsString(json_password)) {
            user_data->password = mx_strdup((const char *) encrypt_password((const char *) json_password->valuestring));
        } else {
            logging_to_file("Could not parse the \"data\" fields from a cJSON object", JSON_ERROR);
            respond_status(client_info->ssl, request_type, ERROR_JSON);
            cJSON_Delete(json);
            free(user_data);
            return;
        }
    } else {
        logging_to_file("Could not parse the \"data\" object from a cJSON object", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        cJSON_Delete(json);
        free(user_data);
        return;
    }

    user_data->id = client_info->id;
    user_data->username = mx_strdup((const char *) client_info->username);
    user_data->updated_at = time(NULL);

    if (!database_update_user(user_data)) {
        logging_to_file("Could not update user data in the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        cJSON_Delete(json);
        free(user_data);
        return;
    }

    t_user_data *new_user_data = database_fetch_user_data(user_data->username);

    if (!new_user_data) {
        logging_to_file("Could not get user data from the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        cJSON_Delete(json);
        free(user_data);
        return;
    }

    respond_auth_request(client_info->ssl, request_type, SUCCESS, new_user_data);
    record_status_log("Successfully updated password for the user", client_info->username);
    free(user_data);
    free(new_user_data);
    cJSON_Delete(json);
    return;
}

void search_users_handler(t_client_info *client_info) {
    t_req_type request_type = GET_USERS_FOR_SEARCH;
    t_list *user_list = database_fetch_user_list(client_info->id);

    if (!user_list) {
        logging_to_file("Users are missing from the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        return;
    }

    respond_user_search(client_info->ssl, SUCCESS, user_list);
    free(user_list);
    return;
}

void process_chat_creation(t_client_info *client_info, char *json_string) {
    t_req_type request_type = ADD_CHAT;
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        return;
    }

    const cJSON *json_data_obj = cJSON_GetObjectItemCaseSensitive(json, "data");
    t_chat *chat_data = (t_chat *) malloc(sizeof(t_chat));
    chat_data->title = NULL;
    chat_data->current_user.id = client_info->id;

    if (cJSON_IsObject(json_data_obj)) {
        const cJSON *json_invitee_user_id = cJSON_GetObjectItemCaseSensitive(json_data_obj, "invitee_user_id");

        if (cJSON_IsNumber(json_invitee_user_id)) {
            chat_data->invitee_user.id = json_invitee_user_id->valueint;
        } else {
            logging_to_file("Could not parse the \"data\" fields from a cJSON object", JSON_ERROR);
            respond_status(client_info->ssl, request_type, ERROR_JSON);
            cJSON_Delete(json);
            free(chat_data);
            return;
        }
    } else {
        logging_to_file("Could not parse the \"data\" object from a cJSON object", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        cJSON_Delete(json);
        free(chat_data);
        return;
    }

    char *invitee_username = database_fetch_username(chat_data->invitee_user.id);

    if (invitee_username == NULL) {
        logging_to_file("The user does not exist in the database", DB_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        cJSON_Delete(json);
        free(chat_data);
        return;
    }

    chat_data->created_at = time(NULL);
    chat_data->current_user.created_at = time(NULL);
    chat_data->invitee_user.created_at = time(NULL);
    t_chat *new_chat_data = database_add_chat_entry(chat_data);

    if (!new_chat_data) {
        logging_to_file("Could not add chat to the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        cJSON_Delete(json);
        free(chat_data);
        return;
    }

    respond_add_chat(client_info->ssl, SUCCESS, new_chat_data);
    record_status_log("Successfully added chat for the user", client_info->username);
    free(chat_data);
    free(new_chat_data);
    cJSON_Delete(json);
    return;
}

void retrieve_user_chats(t_client_info *client_info) {
    t_req_type request_type = GET_CHATS;
    t_list *chat_list = database_fetch_user_chats(client_info->id);

    if (!chat_list) {
        logging_to_file("User chats are missing from the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        return;
    }

    respond_get_chats(client_info->ssl, SUCCESS, chat_list);
    free(chat_list);
    return;
}

void retrieve_chat_messages(t_client_info *client_info, char *json_string) {
    t_req_type request_type = GET_MESSAGES;
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        return;
    }

    const cJSON *json_data_obj = cJSON_GetObjectItemCaseSensitive(json, "data");
    int chat_id;

    if (cJSON_IsObject(json_data_obj)) {
        const cJSON *json_chat_id = cJSON_GetObjectItemCaseSensitive(json_data_obj, "chat_id");

        if (cJSON_IsNumber(json_chat_id)) {
            chat_id = json_chat_id->valueint;
        } else {
            logging_to_file("Could not parse the \"data\" fields from a cJSON object", JSON_ERROR);
            respond_status(client_info->ssl, request_type, ERROR_JSON);
            cJSON_Delete(json);
            return;
        }
    } else {
        logging_to_file("Could not parse the \"data\" from a cJSON object", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        cJSON_Delete(json);
        return;
    }

    t_list *message_list = database_fetch_chat_messages(chat_id);

    if (!message_list) {
        logging_to_file("Chat messages are missing from the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        cJSON_Delete(json);
        return;
    }

    respond_get_messages(client_info->ssl, SUCCESS, message_list);
    free(message_list);
    cJSON_Delete(json);
    return;
}

void process_message_addition(t_client_info *client_info, char *json_string) {
    t_req_type request_type = ADD_MESSAGE;
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        return;
    }

    const cJSON *json_data_obj = cJSON_GetObjectItemCaseSensitive(json, "data");
    t_message_data *msg_data = (t_message_data *) malloc(sizeof(t_message_data));
    msg_data->user_id = client_info->id;

    if (cJSON_IsObject(json_data_obj)) {
        const cJSON *json_chat_id = cJSON_GetObjectItemCaseSensitive(json_data_obj, "chat_id");
        const cJSON *json_body = cJSON_GetObjectItemCaseSensitive(json_data_obj, "body");

        if (cJSON_IsNumber(json_chat_id) && cJSON_IsString(json_body)) {
            msg_data->chat_id = json_chat_id->valueint;
            msg_data->body = mx_strdup((const char *)json_body->valuestring);
        } else {
            logging_to_file("Could not parse the \"data\" fields from a cJSON object", JSON_ERROR);
            respond_status(client_info->ssl, request_type, ERROR_JSON);
            free(msg_data);
            cJSON_Delete(json);
            return;
        }
    } else {
        logging_to_file("Could not parse the \"data\" object from a cJSON object", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        free(msg_data);
        cJSON_Delete(json);
        return;
    }

    msg_data->created_at = time(NULL);
    t_message_data *new_msg_data = database_add_message_entry(msg_data);

    if (!new_msg_data) {
        logging_to_file("Could not post message in the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        free(msg_data);
        cJSON_Delete(json);
        return;
    }

    respond_message(client_info->ssl, request_type, SUCCESS, new_msg_data);
    record_status_log("Successfully added message for the user", client_info->username);
    free(msg_data);
    free(new_msg_data);
    cJSON_Delete(json);
    return;
}

void process_message_update(t_client_info *client_info, char *json_string) {
    t_req_type request_type = UPDATE_MESSAGE;
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        return;
    }

    const cJSON *json_data_obj = cJSON_GetObjectItemCaseSensitive(json, "data");
    t_message_data *msg_data = (t_message_data *) malloc(sizeof(t_message_data));

    if (cJSON_IsObject(json_data_obj)) {
        const cJSON *json_msg_id = cJSON_GetObjectItemCaseSensitive(json_data_obj, "message_id");
        const cJSON *json_body = cJSON_GetObjectItemCaseSensitive(json_data_obj, "body");

        if (cJSON_IsNumber(json_msg_id) && cJSON_IsString(json_body)) {
            msg_data->message_id = json_msg_id->valueint;
            msg_data->body = json_body->valuestring;
        } else {
            logging_to_file("Could not parse the \"data\" fields from a cJSON object", JSON_ERROR);
            respond_status(client_info->ssl, request_type, ERROR_JSON);
            free(msg_data);
            cJSON_Delete(json);
            return;
        }
    } else {
        logging_to_file("Could not parse the \"data\" from a cJSON object", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        free(msg_data);
        cJSON_Delete(json);
        return;
    }

    msg_data->updated_at = time(NULL);
    t_message_data *new_msg_data = database_modify_message(msg_data);

    if (!new_msg_data) {
        logging_to_file("Message is missing from the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        free(msg_data);
        cJSON_Delete(json);
        return;
    }

    respond_message(client_info->ssl, request_type, SUCCESS, new_msg_data);
    record_status_log("Successfully updated message for the user", client_info->username);
    free(msg_data);
    free(new_msg_data);
    cJSON_Delete(json);
    return;
}

void process_message_deletion(t_client_info *client_info, char *json_string) {
    t_req_type request_type = DELETE_MESSAGE;
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        return;
    }

    const cJSON *json_data_obj = cJSON_GetObjectItemCaseSensitive(json, "data");
    t_message_data *msg_data = (t_message_data *) malloc(sizeof(t_message_data));

    if (cJSON_IsObject(json_data_obj)) {
        const cJSON *json_msg_id = cJSON_GetObjectItemCaseSensitive(json_data_obj, "message_id");

        if (cJSON_IsNumber(json_msg_id)) {
            msg_data->message_id = json_msg_id->valueint;
        } else {
            logging_to_file("Could not parse the \"data\" fields from a cJSON object", JSON_ERROR);
            respond_status(client_info->ssl, request_type, ERROR_JSON);
            free(msg_data);
            cJSON_Delete(json);
            return;
        }
    } else {
        logging_to_file("Could not parse the \"data\" from a cJSON object", JSON_ERROR);
        respond_status(client_info->ssl, request_type, ERROR_JSON);
        free(msg_data);
        cJSON_Delete(json);
        return;
    }

    msg_data->deleted_at = time(NULL);
    t_message_data *new_msg_data = database_remove_message(msg_data);

    if (!new_msg_data) {
        logging_to_file("Message is missing from the database", ERROR);
        respond_status(client_info->ssl, request_type, ERROR_DB);
        free(msg_data);
        cJSON_Delete(json);
        return;
    }

    respond_message(client_info->ssl, request_type, SUCCESS, new_msg_data);
    record_status_log("Successfully deleted message for the user", client_info->username);
    free(msg_data);
    free(new_msg_data);
    cJSON_Delete(json);
    return;
}

