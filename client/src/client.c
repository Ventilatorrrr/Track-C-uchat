#include "client.h"
#include "api.h"

// Глобальні змінні для зберігання інформації про сервер, клієнта та чергу даних
t_server *server_info;
t_client *client_info;
GAsyncQueue *data_queue;

// Логування повідомлень у файл
void log_to_file(char *message, t_log_type log_type) {
    FILE *log_file = fopen(LOG_FILE, "a"); // Відкриваємо файл для запису в режимі додавання
    time_t current_time;
    struct tm *time_info;
    char time_string[80];
    time(&current_time); // Отримуємо поточний час
    time_info = localtime(&current_time); // Конвертуємо час у локальний формат
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", time_info); // Форматуємо час у рядок

    // Вибір типу повідомлення для запису у лог
    switch (log_type) {
        case INFO:
            fprintf(log_file, "[%s]\tINFO\t\tPID %d\t%s\n", time_string, getpid(), message);
            break;
        case ERROR:
            fprintf(log_file, "[%s]\tERROR\t\tPID %d\t%s: %s\n", time_string, getpid(), message, strerror(errno));
            break;
        case JSON_ERROR:
            fprintf(log_file, "[%s]\tJSON_ERROR\tPID %d\t%s: %s\n", time_string, getpid(), message, strerror(errno));
            break;
        case SSL_ERROR:
            fprintf(log_file, "[%s]\tSSL_ERROR\tPID %d\t%s: %s\n", time_string, getpid(), message, strerror(errno));
            ERR_print_errors_fp(log_file); // Друкуємо помилки SSL
            break;
        default:
            break;
    }

    fclose(log_file); // Закриваємо файл
}

// Створення SSL контексту для клієнта
SSL_CTX *create_context(void) {
    const SSL_METHOD *method;
    method = TLS_client_method(); // Використовуємо метод клієнта для TLS
    SSL_CTX *context;
    context = SSL_CTX_new(method); // Створюємо новий SSL контекст
    return context;
}

// Звільнення ресурсів і завершення роботи клієнта
void free_and_exit(void) {
    if (client_info->client_socket) {
        shutdown(client_info->client_socket, SHUT_RDWR); // Завершення сокета
        close(client_info->client_socket); // Закриття сокета
    }

    if (client_info->ssl) {
        SSL_shutdown(client_info->ssl); // Завершення SSL з'єднання
        SSL_free(client_info->ssl); // Звільнення SSL структури
    }

    if (client_info->context) {
        SSL_CTX_free(client_info->context); // Звільнення SSL контексту
    }

    free(client_info); // Звільнення пам'яті клієнта
    free(server_info); // Звільнення пам'яті сервера
    exit(EXIT_FAILURE);
}

// Потік контролера, який викликає основну функцію контролера
gpointer controller_thread(gpointer data) {
    controller(); // Виконання логіки контролера
    (void)data; // Уникнення попереджень про невикористаний параметр
    return NULL;
}

// Перевірка черги даних та їх обробка
gboolean check_and_process_data(void) {
    char *json_string = (char *)g_async_queue_try_pop(data_queue); // Забираємо дані з черги

    if (json_string != NULL) {
        g_idle_add_full(G_PRIORITY_HIGH_IDLE, process_data_from_controller, json_string, NULL); // Додаємо обробку даних у головний цикл
    }

    return TRUE; // Продовжуємо викликати функцію
}

// Головна функція програми
int main(int argc, char **argv) {
    // Перевірка аргументів командного рядка
    if (argc != 3) {
        printf("usage: %s [ip] [port]\n", argv[0]); // Виведення інструкції використання
        exit(EXIT_SUCCESS);
    }

    // Ініціалізація структури сервера
    server_info = (t_server *) malloc(sizeof(t_server));
    server_info->address.sin_family = AF_INET; // Використання IPv4
    server_info->address.sin_port = htons(atoi(argv[2])); // Встановлення порту

    // Конвертація IP адреси
    if (inet_pton(AF_INET, argv[1], &(server_info->address.sin_addr)) <= 0) {
        perror("Could not convert the network address");
        log_to_file("Could not convert the network address", ERROR);
        exit(EXIT_FAILURE);
    }

    // Ініціалізація структури клієнта
    client_info = (t_client *) malloc(sizeof(t_client));
    client_info->client_socket = socket(AF_INET, SOCK_STREAM, 0); // Створення сокета

    if (client_info->client_socket < 0) {
        perror("Socket creation failed");
        log_to_file("Socket creation failed", ERROR);
        free_and_exit();
    }

    // Підключення до сервера
    if (connect(client_info->client_socket, (struct sockaddr *)&(server_info->address), sizeof(server_info->address)) != 0) {
        perror("Couldn't connect with the server");
        log_to_file("Couldn't connect with the server", ERROR);
        free_and_exit();
    }

    // Ініціалізація SSL бібліотеки
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *context = create_context();
    SSL *ssl;

    if (!context) {
        perror("Unable to create SSL context");
        log_to_file("Unable to create SSL context", ERROR);
        free_and_exit();
    }

    client_info->context = context;
    ssl = SSL_new(context); // Створення нової SSL структури

    if (!ssl) {
        perror("Creation of a new SSL structure failed");
        log_to_file("Creation of a new SSL structure failed", ERROR);
        free_and_exit();
    }

    client_info->ssl = ssl;

    // Налаштування SSL на файл дескриптор
    if (!SSL_set_fd(client_info->ssl, client_info->client_socket)) {
        perror("Unable to set file descriptor as input/output device for TLS/SSL side");
        log_to_file("Unable to set file descriptor as input/output device for TLS/SSL side", ERROR);
        free_and_exit();
    }

    // Виконання SSL з'єднання
    if (SSL_connect(client_info->ssl) != 1) {
        perror("The TLS/SSL handshake was not successful");
        log_to_file("The TLS/SSL handshake was not successful", ERROR);
        free_and_exit();
    }

    // Ініціалізація GTK
    gtk_init(&argc, &argv);
    data_queue = g_async_queue_new(); // Створення асинхронної черги для даних
    GThread *thread;
    thread = g_thread_new("worker_thread", controller_thread, NULL); // Створення потоку контролера
    g_timeout_add(100, (GSourceFunc)check_and_process_data, NULL); // Перевірка даних у черзі кожні 100 мс
    gtk_initialisation(); // Ініціалізація GUI
    g_async_queue_unref(data_queue); // Звільнення черги
    g_thread_join(thread); // Очікування завершення потоку
    return 0;
}

