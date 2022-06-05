#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>

static unsigned int connection = 0;


// Saves the state of a connected client
struct client_state {
    void (*state_fn)(struct client_state *state);
    int fd;
    char *note_ptr;
    char recv_buffer[200];
    unsigned int recv_buffer_size;
};


// Helper function to send a message to the client
void send_message(struct client_state *state, char *message) {
    write(state->fd, message, strlen(message));
}

// Helper function to receive client input.
// Guarantees that recv_buffer is null-terminated if recv_buffer_size > 0.
// Sets recv_buffer_size = 0 on error.
void receive_message(struct client_state *state) {
    // Remove any old message (till the terminating null-character) from the recv_buffer
    if(state->recv_buffer_size > 0) {
        size_t msg_size = strlen(state->recv_buffer) + 1;
        if(state->recv_buffer_size > msg_size) {
            memmove(state->recv_buffer, &state->recv_buffer[msg_size], state->recv_buffer_size - msg_size);
            state->recv_buffer_size -= msg_size;
        } else {
            state->recv_buffer_size = 0;
        }
    }
    // Try to receive something while skipping single newlines
    char *newline = NULL;
    while(1) {
        // Send the prompt
        send_message(state, "> ");
        // Read until newline
        while(1) {
            // Parse any data that's in the buffer
            newline = memchr(state->recv_buffer, '\n', state->recv_buffer_size);
            if(newline == NULL) {
                // Nothing in the buffer, read more data from socket
                size_t buffer_space = sizeof(state->recv_buffer) - state->recv_buffer_size;
                if(buffer_space == 0) {
                    // Read 200 bytes without newline. Sth's wrong. Aborting.
                    state->recv_buffer_size = 0;
                    return;
                }
                ssize_t recv_size = read(state->fd, &state->recv_buffer[state->recv_buffer_size], buffer_space);
                if(recv_size > 0) {
                    state->recv_buffer_size += recv_size;
                } else {
                    // Broken pipe
                    state->recv_buffer_size = 0;
                    return;
                }
                continue;
            }
            break;
        }
        // Remove single newlines
        if(newline == state->recv_buffer) {
            if(state->recv_buffer_size > 1) {
                memmove(state->recv_buffer, &state->recv_buffer[1], state->recv_buffer_size - 1);
            }
            state->recv_buffer_size -= 1;
            continue;
        }
        break;
    }
    // Got something, replace newline with terminating null-character and return
    *newline = '\0';

    fprintf(stderr, "%06u Recv: %.*s\n", connection, strlen(state->recv_buffer), state->recv_buffer);
}

// Checks if an entered password matches.
// Password is stored with high security Caesar encryption
// over the range of printable non whitespace ascii chars.
// int check_password(char *input) {
//     const char *password = "vX|{9]m-<[|"; //N0TSo5Ecr3T
//     const int pwlen = strlen(password);
//     if(strlen(input) != pwlen) {
//         return 0;
//     }
//     for(int i = 0; i < pwlen; ++i) {
//         if((((input[i]-33+40)%94)+33) != password[i]) {
//             return 0;
//         }
//     }
//     return 1;
// }

// Checks if the password is "FUZZ"
// int check_password(char *input) {
//     if(strlen(input) != 4) {
//         return 0;
//     }
//     if(input[0] == 'F' && input[1] == 'U' && input[2] == 'Z' && input[3] == 'Z') {
//         return 1;
//     }
// }

// Accepts all passwords
int check_password(char *input) {
    return 1;
}


//=========================
// State machine functions
//=========================

void state_ask_name(struct client_state *state);
void state_main_menu(struct client_state *state);
void state_set_note(struct client_state *state);
void state_get_note(struct client_state *state);
void state_secret_pass(struct client_state *state);
void state_secret_menu(struct client_state *state);
void state_delete_note(struct client_state *state);

void state_ask_name(struct client_state *state) {
    // Ask for a name
    send_message(state, "Please enter your name:\n");
    receive_message(state);
    if(state->recv_buffer_size == 0) {
        state->state_fn = NULL;
        return;
    }
    // Send a welcome message
    char msg[sizeof("Welcome !\n") + strlen(state->recv_buffer) + 1];
    strcpy(msg, "Welcome ");
    strcat(msg, state->recv_buffer);
    strcat(msg, "!\n");
    send_message(state, msg);
    // Go to next state
    state->state_fn = state_main_menu;
}

void state_main_menu(struct client_state *state) {
    // Ask what to do
    send_message(state, "\n[MAIN MENU]\n");
    send_message(state, "setnote: Save a note in the system\n");
    send_message(state, "getnote: Print the saved note\n");
    send_message(state, "secret: Access the super secret special menu\n");
    send_message(state, "quit: Exit the system\n");
    receive_message(state);
    if(state->recv_buffer_size == 0 || strcmp(state->recv_buffer, "quit") == 0) {
        state->state_fn = NULL;
    } else if(strcmp(state->recv_buffer, "setnote") == 0) {
        state->state_fn = state_set_note;
    } else if(strcmp(state->recv_buffer, "getnote") == 0) {
        state->state_fn = state_get_note;
    } else if(strcmp(state->recv_buffer, "secret") == 0) {
        state->state_fn = state_secret_pass;
    } else {
        send_message(state, "Uhmm, what?\n");
    }
}

void state_set_note(struct client_state *state) {
    // Ask for a note to save
    send_message(state, "\nPlease enter your note:\n");
    receive_message(state);
    if(state->recv_buffer_size == 0) {
        state->state_fn = NULL;
        return;
    }
    // Save it in our client state
    if(state->note_ptr != NULL) {
        free(state->note_ptr);
    }
    state->note_ptr = (char *) malloc(strlen(state->recv_buffer) + 1);
    strcpy(state->note_ptr, state->recv_buffer);
    send_message(state, "Note saved!\n");
    state->state_fn = state_main_menu;
}

void state_get_note(struct client_state *state) {
    // Print the saved note if it exists
    if(state->note_ptr != NULL) {
        send_message(state, "\nHere is your saved note:\n");
        send_message(state, state->note_ptr);
        send_message(state, "\n");
    } else {
        send_message(state, "\nNo note saved yet...\n");
    }
    state->state_fn = state_main_menu;
}

void state_secret_pass(struct client_state *state) {
    // Ask for the secret menu password
    send_message(state, "\nPlease enter the password for the secret menu:\n");
    receive_message(state);
    if(state->recv_buffer_size == 0) {
        state->state_fn = NULL;
        return;
    }
    if(check_password(state->recv_buffer)) {
        send_message(state, "Correct!\n");
        state->state_fn = state_secret_menu;
    } else {
        send_message(state, "Nope!\n");
        state->state_fn = state_main_menu;
    }
}

void state_secret_menu(struct client_state *state) {
    // Ask what to do
    send_message(state, "\n[SECRET MENU]\n");
    send_message(state, "delnote: Delete a saved note\n");
    send_message(state, "back: Go back to main menu\n");
    receive_message(state);
    if(state->recv_buffer_size == 0) {
        state->state_fn = NULL;
    } else if(strcmp(state->recv_buffer, "delnote") == 0) {
        state->state_fn = state_delete_note;
    } else if(strcmp(state->recv_buffer, "back") == 0) {
        state->state_fn = state_main_menu;
    } else {
        send_message(state, "Nonononono!\n");
    }
}

void state_delete_note(struct client_state *state) {
    if(state->note_ptr != NULL) {
        // BUG: we casually forget here to set note_ptr = NULL,
        // provoking a use-after-free or double-free later
        free(state->note_ptr);
        send_message(state, "It's gone!\n");
        state->state_fn = state_secret_menu;
        
        // // Ask for confirmation
        // send_message(state, "\nReally delete? (y/n)\n");
        // receive_message(state);
        // if(state->recv_buffer_size == 0) {
        //     state->state_fn = NULL;
        //     return;
        // } else if(strcmp(state->recv_buffer, "y") == 0) {
        //     // BUG: we casually forget here to set note_ptr = NULL,
        //     // provoking a use-after-free or double-free later
        //     free(state->note_ptr);
        //     send_message(state, "It's gone!\n");
        //     state->state_fn = state_secret_menu;
        // } else {
        //     state->state_fn = state_secret_menu;
        // }
    } else {
        send_message(state, "\nThere is no note saved currently...\n");
        state->state_fn = state_secret_menu;
    }
}

//=========================
// State machine end
//=========================


// Setup client state and loop over our simple state machine
void handle_client(int client_fd) {
    connection++;

    struct client_state cstate = {
        .state_fn = state_ask_name,
        .fd = client_fd,
        .note_ptr = NULL,
        .recv_buffer_size = 0
    };
    while(cstate.state_fn != NULL) {
        cstate.state_fn(&cstate);
    }
}


// Open a TCP socket on port 5000 and listen for connections.
// Client connections are then handled by handle_client().
int main(int argc, char *argv[]) {
    // Prevent SIGPIPE crashing the server when a client looses connection
    struct sigaction sa;
    sa.sa_handler = SIG_IGN;
    sa.sa_flags = SA_RESTART;
    sigaction(SIGPIPE, &sa, NULL);
    //signal(SIGPIPE, SIG_IGN);

    // Open socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if(socket_fd == -1) {
        perror("Failed to open socket");
        return 1;
    }

    // Set server address
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(5000);

    // Set SO_REUSEADDR, useful for locally testing a crashing application
    int flag = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag)) < 0) {  
        perror("Failed to set option SO_REUSEADDR");  
    }

    // Bind to address
    if(bind(socket_fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) < 0) {
        perror("Failed to bind to address");
        return 1;
    }

    // Start listening on socket
    if(listen(socket_fd, 1) < 0) {
        perror("Failed to start listening on socket");
        return 1;
    }

    // Accept clients in a loop
    while(1) {
        // Accept an incoming connection
#ifndef LOG_SILENT
        printf("Waiting for connections...\n");
#endif
	    struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd = accept(socket_fd, (struct sockaddr*) &client_addr, &client_addr_len);
        if(client_fd < 0) {
            perror("Failed to accept connection");
            continue;
        }

        // Do something with it
#ifndef LOG_SILENT
        printf("%06u Client connected!\n", connection);
#endif
        handle_client(client_fd);
        
        // Close connection
#ifndef LOG_SILENT
        printf("%06u Client disconnected!\n", connection);
#endif
        if(close(client_fd) < 0) {
            perror("Failed to close client connection");
        }
    }

	return 0;
}
