#include "api.h"

void *manage_thread(void *arg) {
    t_client_info *client_info = (t_client_info *) arg;
    char *json_string = NULL;
    t_req_type request_type;

    while (true) {
        json_string = fetch_client_data(client_info->ssl);

        if (!json_string) {
            continue;
        }

        request_type = identify_request_type(json_string);
        handle_client_request(client_info, request_type, json_string);
        mx_strdel(&json_string);
    }

    return NULL;
}

char *fetch_client_data(SSL *ssl) {
    char *buffer = (char *) malloc(BUF_SIZE * sizeof(char));
    int bytes_read = 0;
    int total_bytes_read = 0;

    while (true) {
        bytes_read = SSL_read(ssl, buffer + total_bytes_read, BUF_SIZE - total_bytes_read);

        if (bytes_read <= 0) {
            int error_code = SSL_get_error(ssl, bytes_read);

            if (error_code == SSL_ERROR_WANT_READ
                || error_code == SSL_ERROR_WANT_WRITE) {
                logging_to_file("There is still unprocessed data available at the TLS/SSL connection. Continue reading...", SSL_ERROR);
                continue;
            } else {
                logging_to_file("Connection is closed", SSL_ERROR);
                pthread_exit(NULL);
                return NULL;
            }
        }

        total_bytes_read += bytes_read;

        if (total_bytes_read >= BUF_SIZE) {
            logging_to_file("Buffer for reading is overflowing", ERROR);
            return NULL;
        } else if (buffer[total_bytes_read] == '\0') {
            break;
        }
    }

    return mx_strdup(buffer);
}

t_req_type identify_request_type(char *json_string) {
    cJSON *json = cJSON_Parse(json_string);

    if (!json) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            logging_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        }

        return UNKNOWN_REQUEST;
    }

    t_req_type request_type;
    const cJSON *json_req_type = cJSON_GetObjectItem(json, "request_type");

    if (!cJSON_IsNumber(json_req_type)
        || json_req_type->valueint < 0
        || json_req_type->valueint >= REQUEST_TYPE_COUNT) {
        request_type = UNKNOWN_REQUEST;
        logging_to_file("Could not parse the \"request_type\" field from a cJSON object", ERROR);
        cJSON_Delete(json);
        return request_type;
    }

    request_type = json_req_type->valueint;
    cJSON_Delete(json);
    return request_type;
}

