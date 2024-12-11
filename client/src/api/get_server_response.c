#include "api.h"
#include "gui.h"

// Основна функція контролера, яка читає дані з сокета та передає їх у чергу для обробки
void *controller(void) {
    char *json_string = NULL;

    // Безкінечний цикл для читання даних із сокета
    while (true) {
        json_string = read_client_socket(); // Читаємо дані з сокета

        if (!json_string) {
            continue; // Якщо даних немає, продовжуємо очікування
        }

        g_async_queue_push(data_queue, json_string); // Додаємо отримані дані у асинхронну чергу для подальшої обробки
    }

    return NULL; // Завершення функції (хоча цикл нескінченний)
}

// Обробка даних із черги, викликана асинхронно
int process_data_from_controller(gpointer data) {
    char *json_string = (char *)data; // Перетворення даних у рядок JSON
    t_request_type request_type = parse_request_type(json_string); // Визначення типу запиту
    process_server_response(request_type, json_string); // Обробка запиту відповідно до типу
    g_free(json_string); // Звільнення пам'яті, виділеної для JSON-рядка
    return G_SOURCE_REMOVE; // Повертаємо значення для видалення джерела з головного циклу GTK
}

// Функція для читання даних із сокета клієнта
char *read_client_socket(void) {
    char *buffer = (char *) malloc(BUF_SIZE * sizeof(char)); // Виділення буфера для читання даних
    int bytes_read = 0; // Кількість прочитаних байтів за один раз
    int total_bytes_read = 0; // Загальна кількість прочитаних байтів

    // Безкінечний цикл для читання даних з TLS/SSL з'єднання
    while (true) {
        bytes_read = SSL_read(client_info->ssl, buffer + total_bytes_read, BUF_SIZE - total_bytes_read); // Читання даних

        if (bytes_read <= 0) { // Якщо сталася помилка або з'єднання закрито
            int error_code = SSL_get_error(client_info->ssl, bytes_read);

            if (error_code == SSL_ERROR_WANT_READ
                 || error_code == SSL_ERROR_WANT_WRITE) {
                // Якщо потрібна додаткова операція читання або запису, продовжуємо
                log_to_file("There is still unprocessed data available at the TLS/SSL connection. Continue reading...", SSL_ERROR);
                continue;
            } else {
                // Якщо з'єднання закрито або сталася критична помилка
                log_to_file("Connection is closed", SSL_ERROR);
                gtk_widget_show(reconection_label); // Відображення повідомлення про реконект
                gtk_label_set_text(GTK_LABEL(reconection_label), (const gchar*) "Reconecting...");
                gtk_widget_set_opacity(reconection_label, 1.0);
                show_reconnect(); // Відображення GIF анімації реконекту
                reconnect_to_server(); // Спроба реконекту
                gtk_label_set_text(GTK_LABEL(reconection_label), ""); // Очищення повідомлення
                gtk_widget_set_opacity(reconection_label, 0.0);
                recon_closed(); // Закриття анімації реконекту
                return NULL; // Повертаємо NULL у разі помилки
            }
        }

        total_bytes_read += bytes_read; // Оновлюємо загальну кількість прочитаних байтів

        if (total_bytes_read >= BUF_SIZE) { // Якщо буфер переповнений
            log_to_file("Buffer for reading is overflowing", SSL_ERROR);
            return NULL;
        } else if (buffer[total_bytes_read] == '\0') { // Якщо досягнуто кінця рядка
            break;
        }
    }

    return mx_strdup(buffer); // Повертаємо копію буфера
}

// Функція для реконекту до сервера
void reconnect_to_server(void) {
    log_to_file("The reconnection to server is started", INFO);
    perror("The reconnection to server is started");

    while (true) {
        sleep(3); // Затримка перед спробою реконекту
        client_info->client_socket = socket(AF_INET, SOCK_STREAM, 0); // Створюємо новий сокет

        if (client_info->client_socket < 0) { // Якщо створення сокета не вдалося
            log_to_file("Socket creation failed", ERROR);
            continue;
        }

        if (connect(client_info->client_socket, (struct sockaddr *) &(server_info->address), sizeof(server_info->address)) != 0) {
            // Якщо підключення не вдалося
            log_to_file("Couldn't connect with the server", ERROR);
            close(client_info->client_socket); // Закриваємо сокет
            continue;
        }

        client_info->ssl = SSL_new(client_info->context); // Створюємо нову SSL структуру

        if (!client_info->ssl) { // Якщо створення SSL структури не вдалося
            log_to_file("Creation of a new SSL structure failed", ERROR);
            close(client_info->client_socket);
            continue;
        }

        if (!SSL_set_fd(client_info->ssl, client_info->client_socket)) { // Якщо не вдалося прив'язати SSL до сокета
            log_to_file("Unable to set file descriptor as input/output device for TLS/SSL side", SSL_ERROR);
            close(client_info->client_socket);
            SSL_free(client_info->ssl);
            continue;
        }

        if (SSL_connect(client_info->ssl) != 1) { // Якщо TLS/SSL рукопотиск не вдалося виконати
            log_to_file("The TLS/SSL handshake was not successful", SSL_ERROR);
            close(client_info->client_socket);
            SSL_free(client_info->ssl);
            continue;
        }

        log_to_file("The reconnection to server was successful", INFO);
        perror("The reconnection to server was successful");
        break; // Виходимо з циклу у разі успішного реконекту
    }
}

// Парсинг типу запиту з JSON
t_request_type parse_request_type(char *json_string) {
    cJSON *json = cJSON_Parse(json_string); // Парсинг JSON рядка

    if (!json) { // Якщо JSON не вдалося розпарсити
        const char *error_ptr = cJSON_GetErrorPtr();

        if (error_ptr != NULL) {
            log_to_file("Could not parse the cJSON object from client", JSON_ERROR);
        }

        return UNKNOWN_REQUEST; // Повертаємо тип запиту як невідомий
    }

    t_request_type request_type;
    const cJSON *json_req_type = cJSON_GetObjectItemCaseSensitive(json, "request_type"); // Отримуємо поле "request_type"

    if (!cJSON_IsNumber(json_req_type)
        || json_req_type->valueint < 0
        || json_req_type->valueint >= REQUEST_TYPE_COUNT) {
        // Якщо значення поля "request_type" некоректне
        request_type = UNKNOWN_REQUEST;
        log_to_file("Could not parse the \"request_type\" field from a cJSON object", JSON_ERROR);
        cJSON_Delete(json);
        return request_type;
    }

    request_type = json_req_type->valueint; // Визначаємо тип запиту
    cJSON_Delete(json); // Видаляємо об'єкт JSON
    return request_type;
}


