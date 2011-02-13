#define PW_MIN_LENGTH 4
typedef struct pw_cb_data
{
	const void *password;
	const char *prompt_info;
} PW_CB_DATA;

int init_io();
int password_callback(char *, int, int, PW_CB_DATA *);

