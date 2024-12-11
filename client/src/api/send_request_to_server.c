#include "api.h"

// Відправка запиту на реєстрацію користувача
void send_registration_request(SSL *ssl, t_user_data *user_data) {
    t_request_type request_type = REGISTER; // Встановлення типу запиту
    char *json_string = NULL; // Строка для JSON
    cJSON *json = cJSON_CreateObject(); // Створення JSON-об'єкта
    cJSON *json_data_obj = cJSON_CreateObject(); // Створення об'єкта для даних

    // Перевірка на успішне створення об'єктів
    if (!json || !json_data_obj) {
        log_to_file("Could not create the cJSON object to send registration request to the server", JSON_ERROR);
        return;
    }

    // Додавання полів у JSON-об'єкт
    if (!cJSON_AddNumberToObject(json, "request_type", request_type)
        || !cJSON_AddItemToObject(json, "data", json_data_obj)
        || !cJSON_AddStringToObject(json_data_obj, "username", user_data->username)
        || !cJSON_AddStringToObject(json_data_obj, "password", user_data->password)) {
        log_to_file("Could not add the data in the cJSON object to send registration request to the server", JSON_ERROR);
        cJSON_Delete(json);
        return;
    }

    // Перетворення JSON у строку
    json_string = cJSON_Print(json);

    // Відправка JSON через SSL
    int bytes_written = SSL_write(ssl, json_string, strlen(json_string));
    if (bytes_written <= 0) {
        log_to_file("Could not write JSON string over the TLS/SSL connection to send registration request to the server", JSON_ERROR);
    }

    // Очищення ресурсів
    free(json_string);
    cJSON_Delete(json);
    return;
}

// Відправка запиту на авторизацію (універсальна функція для логіну або реєстрації)
void send_auth_with_request_type(SSL *ssl, t_request_type request_type, t_user_data *user_data) {
    char *json_string = NULL;
    cJSON *json = cJSON_CreateObject(); // Створення JSON-об'єкта
    cJSON *json_credentials_obj = cJSON_CreateObject(); // Об'єкт для облікових даних

    // Перевірка на успішне створення об'єктів
    if (!json || !json_credentials_obj) {
        log_to_file("Could not create the cJSON object to send auth request to the server", JSON_ERROR);
        return;
    }

    // Додавання полів у JSON-об'єкт
    if (!cJSON_AddNumberToObject(json, "request_type", request_type)
        || !cJSON_AddItemToObject(json, "credentials", json_credentials_obj)
        || !cJSON_AddStringToObject(json_credentials_obj, "username", user_data->username)
        || !cJSON_AddStringToObject(json_credentials_obj, "password", user_data->password)) {
        log_to_file("Could not add the data in the cJSON object to send auth request to the server", JSON_ERROR);
        cJSON_Delete(json);
        return;
    }

    // Перетворення JSON у строку
    json_string = cJSON_Print(json);

    // Відправка JSON через SSL
    int bytes_written = SSL_write(ssl, json_string, strlen(json_string));
    if (bytes_written <= 0) {
        log_to_file("Could not write JSON string over the TLS/SSL connection to send auth request to the server", JSON_ERROR);
    }

    // Очищення ресурсів
    free(json_string);
    cJSON_Delete(json);
    return;
}

// Відправка запиту на логін користувача
void send_login_request(SSL *ssl, t_user_data *user_data) {
    t_request_type request_type = LOGIN; // Встановлення типу запиту
    send_auth_with_request_type(ssl, request_type, user_data); // Виклик універсальної функції для авторизації
    return;
}

// Відправка запиту на оновлення даних користувача (зміна паролю)
void send_update_user_request(SSL *ssl, t_user_data *user_data, char *password) {
    t_request_type request_type = UPDATE_USER;
    char *json_string = NULL;
    cJSON *json = cJSON_CreateObject(); // Створення JSON-об'єкта
    cJSON *json_credentials_obj = cJSON_CreateObject(); // Об'єкт для облікових даних
    cJSON *json_data_obj = cJSON_CreateObject(); // Об'єкт для нових даних

    // Перевірка на успішне створення об'єктів
    if (!json || !json_credentials_obj || !json_data_obj) {
        log_to_file("Could not create the cJSON object to send UPDATE_USER request to the server", JSON_ERROR);
        return;
    }

    // Додавання полів у JSON-об'єкт
    if (!cJSON_AddNumberToObject(json, "request_type", request_type)
        || !cJSON_AddItemToObject(json, "credentials", json_credentials_obj)
        || !cJSON_AddItemToObject(json, "data", json_data_obj)
        || !cJSON_AddStringToObject(json_credentials_obj, "username", user_data->username)
        || !cJSON_AddStringToObject(json_credentials_obj, "password", user_data->password)
        || !cJSON_AddStringToObject(json_data_obj, "password", password)) {
        log_to_file("Could not add the data in the cJSON object to send UPDATE_USER request to the server", JSON_ERROR);
        cJSON_Delete(json);
        return;
    }

    // Перетворення JSON у строку
    json_string = cJSON_Print(json);

    // Відправка JSON через SSL
    int bytes_written = SSL_write(ssl, json_string, strlen(json_string));
    if (bytes_written <= 0) {
        log_to_file("Could not write JSON string over the TLS/SSL connection to send UPDATE_USER request to the server", JSON_ERROR);
    }

    // Очищення ресурсів
    free(json_string);
    cJSON_Delete(json);
    return;
}

//using send_get_users_for_search_request
void send_get_users_for_search_request(SSL *ssl, t_user_data *user_data) {
    t_request_type request_type = GET_USERS_FOR_SEARCH;
    send_auth_with_request_type(ssl, request_type, user_data);
    return;
}
//using send_add_chat_request
void send_add_chat_request(SSL *ssl, t_user_data *user_data, int invitee_user_id) {
    t_request_type request_type = ADD_CHAT;
    char *json_string = NULL;
    cJSON *json = cJSON_CreateObject();
    cJSON *json_credentials_obj = cJSON_CreateObject();
    cJSON *json_data_obj = cJSON_CreateObject();

    if (!json
        || !json_credentials_obj
        || !json_data_obj) {
        log_to_file("Could not create the cJSON object to send ADD_CHAT request to the server", JSON_ERROR);
        return;
    }

    if (!cJSON_AddNumberToObject(json, "request_type", request_type)
        || !cJSON_AddItemToObject(json, "credentials", json_credentials_obj)
        || !cJSON_AddItemToObject(json, "data", json_data_obj)
        || !cJSON_AddStringToObject(json_credentials_obj, "username", user_data->username)
        || !cJSON_AddStringToObject(json_credentials_obj, "password", user_data->password)
        || !cJSON_AddNumberToObject(json_data_obj, "invitee_user_id", invitee_user_id)) {
        log_to_file("Could not add the data in the cJSON object to send ADD_CHAT request to the server", JSON_ERROR);
        cJSON_Delete(json);
        return;
    }

    json_string = cJSON_Print(json);
    int bytes_written = SSL_write(ssl, json_string, strlen(json_string));

    if (bytes_written <= 0) {
        log_to_file("Could not write JSON string over the TLS/SSL connection to send ADD_CHAT request to the server", JSON_ERROR);
    }

    free(json_string);
    cJSON_Delete(json);
    return;
}
//using send_get_chats_request
void send_get_chats_request(SSL *ssl, t_user_data *user_data) {
    t_request_type request_type = GET_CHATS;
    send_auth_with_request_type(ssl, request_type, user_data);
    return;
}
//using send_get_messages_request
void send_get_messages_request(SSL *ssl, t_user_data *user_data, int chat_id) {
    t_request_type request_type = GET_MESSAGES;
    char *json_string = NULL;
    cJSON *json = cJSON_CreateObject();
    cJSON *json_credentials_obj = cJSON_CreateObject();
    cJSON *json_data_obj = cJSON_CreateObject();

    if (!json
        || !json_credentials_obj
        || !json_data_obj) {
        log_to_file("Could not create the cJSON object to send GET_MESSAGES request to the server", JSON_ERROR);
        return;
    }

    if (!cJSON_AddNumberToObject(json, "request_type", request_type)
        || !cJSON_AddItemToObject(json, "credentials", json_credentials_obj)
        || !cJSON_AddItemToObject(json, "data", json_data_obj)
        || !cJSON_AddStringToObject(json_credentials_obj, "username", user_data->username)
        || !cJSON_AddStringToObject(json_credentials_obj, "password", user_data->password)
        || !cJSON_AddNumberToObject(json_data_obj, "chat_id", chat_id)) {
        log_to_file("Could not add the data in the cJSON object to send GET_MESSAGES request to the server", JSON_ERROR);
        cJSON_Delete(json);
        return;
    }

    json_string = cJSON_Print(json);
    int bytes_written = SSL_write(ssl, json_string, strlen(json_string));

    if (bytes_written <= 0) {
        log_to_file("Could not write JSON string over the TLS/SSL connection to send GET_MESSAGES request to the server", JSON_ERROR);
    }

    free(json_string);
    cJSON_Delete(json);
    return;
}
//using send_add_message_request
void send_add_message_request(SSL *ssl, t_user_data *user_data, t_msg_data *msg_data) {
    t_request_type request_type = ADD_MESSAGE;
    char *json_string = NULL;
    cJSON *json = cJSON_CreateObject();
    cJSON *json_credentials_obj = cJSON_CreateObject();
    cJSON *json_data_obj = cJSON_CreateObject();

    if (!json
        || !json_credentials_obj
        || !json_data_obj) {
        log_to_file("Could not create the cJSON object to send ADD_MESSAGE request to the server", JSON_ERROR);
        return;
    }

    if (!cJSON_AddNumberToObject(json, "request_type", request_type)
        || !cJSON_AddItemToObject(json, "credentials", json_credentials_obj)
        || !cJSON_AddItemToObject(json, "data", json_data_obj)
        || !cJSON_AddStringToObject(json_credentials_obj, "username", user_data->username)
        || !cJSON_AddStringToObject(json_credentials_obj, "password", user_data->password)
        || !cJSON_AddNumberToObject(json_data_obj, "chat_id", msg_data->chat_id)
        || !cJSON_AddStringToObject(json_data_obj, "body", msg_data->body))  {
        log_to_file("Could not add the data in the cJSON object to send ADD_MESSAGE request to the server", JSON_ERROR);
        cJSON_Delete(json);
        return;
    }

    json_string = cJSON_Print(json);
    int bytes_written = SSL_write(ssl, json_string, strlen(json_string));

    if (bytes_written <= 0) {
        log_to_file("Could not write JSON string over the TLS/SSL connection to send ADD_MESSAGE request to the server", JSON_ERROR);
    }

    free(json_string);
    cJSON_Delete(json);
    return;
}
//using send_update_message_request
void send_update_message_request(SSL *ssl, t_user_data *user_data, t_msg_data *msg_data) {
    t_request_type request_type = UPDATE_MESSAGE;
    char *json_string = NULL;
    cJSON *json = cJSON_CreateObject();
    cJSON *json_credentials_obj = cJSON_CreateObject();
    cJSON *json_data_obj = cJSON_CreateObject();

    if (!json
        || !json_credentials_obj
        || !json_data_obj) {
        log_to_file("Could not create the cJSON object to send UPDATE_MESSAGE request to the server", JSON_ERROR);
        return;
    }

    if (!cJSON_AddNumberToObject(json, "request_type", request_type)
        || !cJSON_AddItemToObject(json, "credentials", json_credentials_obj)
        || !cJSON_AddItemToObject(json, "data", json_data_obj)
        || !cJSON_AddStringToObject(json_credentials_obj, "username", user_data->username)
        || !cJSON_AddStringToObject(json_credentials_obj, "password", user_data->password)
        || !cJSON_AddNumberToObject(json_data_obj, "message_id", msg_data->message_id)
        || !cJSON_AddStringToObject(json_data_obj, "body", msg_data->body)) {
        log_to_file("Could not add the data in the cJSON object to send UPDATE_MESSAGE request to the server", JSON_ERROR);
        cJSON_Delete(json);
        return;
    }

    json_string = cJSON_Print(json);
    int bytes_written = SSL_write(ssl, json_string, strlen(json_string));

    if (bytes_written <= 0) {
        log_to_file("Could not write JSON string over the TLS/SSL connection to send UPDATE_MESSAGE request to the server", JSON_ERROR);
    }

    free(json_string);
    cJSON_Delete(json);
    return;
}
//using send_delete_message_request
void send_delete_message_request(SSL *ssl, t_user_data *user_data, t_msg_data *msg_data) {
    t_request_type request_type = DELETE_MESSAGE;
    char *json_string = NULL;
    cJSON *json = cJSON_CreateObject();
    cJSON *json_credentials_obj = cJSON_CreateObject();
    cJSON *json_data_obj = cJSON_CreateObject();

    if (!json
        || !json_credentials_obj
        || !json_data_obj) {
        log_to_file("Could not create the cJSON object to send DELETE_MESSAGE request to the server", JSON_ERROR);
        return;
    }

    if (!cJSON_AddNumberToObject(json, "request_type", request_type)
        || !cJSON_AddItemToObject(json, "credentials", json_credentials_obj)
        || !cJSON_AddItemToObject(json, "data", json_data_obj)
        || !cJSON_AddStringToObject(json_credentials_obj, "username", user_data->username)
        || !cJSON_AddStringToObject(json_credentials_obj, "password", user_data->password)
        || !cJSON_AddNumberToObject(json_data_obj, "message_id", msg_data->message_id)) {
        log_to_file("Could not add the data in the cJSON object to send DELETE_MESSAGE request to the server", JSON_ERROR);
        cJSON_Delete(json);
        return;
    }

    json_string = cJSON_Print(json);
    int bytes_written = SSL_write(ssl, json_string, strlen(json_string));

    if (bytes_written <= 0) {
        log_to_file("Could not write JSON string over the TLS/SSL connection to send DELETE_MESSAGE request to the server", JSON_ERROR);
    }

    free(json_string);
    cJSON_Delete(json);
    return;
}

