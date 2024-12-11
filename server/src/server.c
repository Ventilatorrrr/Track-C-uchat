//server.c
#include "server.h"
#include "api.h"

pthread_mutex_t logging_mutex;
t_list *user_list;

void logging_to_file(char *message, t_loggin_type log_type) {
    pthread_mutex_lock(&logging_mutex);
    FILE *log_file = fopen(LOG_FILE, "a");

    time_t current_time;
    time(&current_time);
    struct tm *time_info;
    time_info = localtime(&current_time);
    char time_string[50];
    strftime(time_string, sizeof(time_string), "%Y-%m-%d %H:%M:%S", time_info);

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
            ERR_print_errors_fp(log_file);
            break;
        case DB_ERROR:
            fprintf(log_file, "[%s]\tDB_ERROR\tPID %d\t%s: %s\n", time_string, getpid(), message, strerror(errno));
            break;
        default:
            break;
    }

    fclose(log_file);
    pthread_mutex_unlock(&logging_mutex);
}

void server_create_daemon(void) {
    pid_t pid = fork();
    pid_t sid = 0;

    if (pid < 0) {
        logging_to_file("Failed to create child process", ERROR);
        exit(EXIT_FAILURE);
    }

    if (pid > 0) {
        printf("Deamon started with pid %d\n", pid);
        char *msg = (char *) malloc(100 * sizeof(char));
        sprintf(msg, "Deamon started with pid %d", pid);
        logging_to_file(msg, INFO);
        free(msg);
        exit(EXIT_SUCCESS);
    }

    umask(0);
    sid = setsid();

    if (sid < 0) {
        logging_to_file("Failed to create session", ERROR);
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
}

int network_create_socket(void) {
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);

    if (server_socket < 0) {
        logging_to_file("Socket creation failed", ERROR);
        exit(EXIT_FAILURE);
    }

    return server_socket;
}

void network_bind_socket(int server_socket, char *port) {
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(atoi(port));
    server_address.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_socket, (struct sockaddr*)&server_address, sizeof(struct sockaddr)) < 0) {
        logging_to_file("Couldn't bind socket", ERROR);
        close(server_socket);
        exit(EXIT_FAILURE);
    }
}

void network_listen_socket(int server_socket) {
    if (listen(server_socket, BACKLOG) < 0) {
        logging_to_file("Couldn't listen for connections", ERROR);
        close(server_socket);
        exit(EXIT_FAILURE);
    }
}

void client_list_cleanup(void) {
    if (user_list == NULL) {
        return;
    }

    while (user_list != NULL) {
        t_list *current = user_list->next;

        if (((t_client_info *)(user_list->data))->client_socket) {
            shutdown(((t_client_info *)(user_list->data))->client_socket, SHUT_RDWR);
            close(((t_client_info *)(user_list->data))->client_socket);
        }

        if (((t_client_info *)(user_list->data))->ssl) {
            SSL_shutdown(((t_client_info *)(user_list->data))->ssl);
            SSL_free(((t_client_info *)(user_list->data))->ssl);
        }

        free(user_list);
        user_list = current;
    }

    user_list = NULL;
}

SSL_CTX *ssl_create_context(void) {
    const SSL_METHOD *method;
    method = TLS_server_method();
    SSL_CTX *context;
    context = SSL_CTX_new(method);

    if (!context) {
        logging_to_file("Unable to create SSL context", SSL_ERROR);
    }

    return context;
}

bool ssl_configure_context(SSL_CTX *context) {
    if (SSL_CTX_use_certificate_file(context, SSL_CERTIFICATE, SSL_FILETYPE_PEM) <= 0) {
        logging_to_file("Couldn't load the certificate into the SSL_CTX", SSL_ERROR);
        return false;
    }

    if (SSL_CTX_use_PrivateKey_file(context, SSL_PRIVATE_KEY, SSL_FILETYPE_PEM) <= 0 ) {
        logging_to_file("Couldn't load the private key into the SSL_CTX", SSL_ERROR);
        return false;
    }

    if (SSL_CTX_check_private_key(context) != 1) {
        logging_to_file("The private key has no consistency with the certificate", SSL_ERROR);
        return false;
    }

    return true;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        printf("usage: %s [port]\n", argv[0]);
        exit(EXIT_SUCCESS);
    }

    if (pthread_mutex_init(&logging_mutex, NULL) != 0) {
        logging_to_file("Mutex initialization failed", ERROR);
        exit(EXIT_FAILURE);
    }

    server_create_daemon();
    int server_socket = network_create_socket();
    network_bind_socket(server_socket, argv[1]);
    network_listen_socket(server_socket);

    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
    SSL_CTX *context = ssl_create_context();
    SSL *ssl;

    if (!context
        || !ssl_configure_context(context)) {
        SSL_CTX_free(context);
        close(server_socket);
        exit(EXIT_FAILURE);
    }

    while (true) {
        int client_socket = accept(server_socket, NULL, NULL);

        if (client_socket < 0) {
            logging_to_file("Couldn't establish connection with client", ERROR);
            break;
        }

        t_client_info *client_info = (t_client_info *) malloc(sizeof(t_client_info));
        client_info->client_socket = client_socket;
        mx_push_back(&user_list, client_info);

        ssl = SSL_new(context);

        if (!ssl) {
            logging_to_file("Creation of a new SSL structure failed", SSL_ERROR);
            break;
        }

        client_info->ssl = ssl;

        if (!SSL_set_fd(client_info->ssl, client_socket)) {
            logging_to_file("Unable to set file descriptor as input/output device for TLS/SSL side", SSL_ERROR);
            break;
        }

        if (SSL_accept(client_info->ssl) != 1) {
            logging_to_file("The TLS/SSL handshake was not successful", SSL_ERROR);
            break;
        }

        pthread_t thread;
        pthread_attr_t thread_attr;
        pthread_attr_init(&thread_attr);

        if (pthread_create(&thread, &thread_attr, manage_thread, client_info) != 0) {
            logging_to_file("Failed to create a thread", ERROR);
            break;
        }

        pthread_detach(thread);
    }

    SSL_CTX_free(context);
    client_list_cleanup();
    close(server_socket);
    exit(EXIT_FAILURE);
}

