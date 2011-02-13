#include <string.h>

#include <openssl/ui.h>
#include <openssl/bio.h>

#include "util.h"

static UI_METHOD *ui_method = NULL;

BIO * bio_out = NULL;
BIO * bio_err = NULL;

void destroy_ui_method(void) {
	if(ui_method) {
		UI_destroy_method(ui_method);
		ui_method = NULL;
	}
}

int init_bio() {
	bio_out = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
	return 0;
}

int password_callback(char *buf, int bufsiz, int verify, PW_CB_DATA *cb_tmp) {
	UI *ui = NULL;
	int res = 0;
	const char *prompt_info = NULL;
	const char *password = NULL;
	PW_CB_DATA *cb_data = (PW_CB_DATA *)cb_tmp;

	if (cb_data) {
		if (cb_data->password)
			password = cb_data->password;
		if (cb_data->prompt_info)
			prompt_info = cb_data->prompt_info;
	}

	if (password) {
		res = strlen(password);
		if (res > bufsiz)
			res = bufsiz;
		memcpy(buf, password, res);
		return res;
	}

	ui = UI_new_method(ui_method);
	if (ui) {
		int ok = 0;
		char *buff = NULL;
		int ui_flags = 0;
		char *prompt = NULL;

		prompt = UI_construct_prompt(ui, "pass phrase",
			prompt_info);

		ui_flags |= UI_INPUT_FLAG_DEFAULT_PWD;
		UI_ctrl(ui, UI_CTRL_PRINT_ERRORS, 1, 0, 0);

		if (ok >= 0)
			ok = UI_add_input_string(ui,prompt,ui_flags,buf,
				PW_MIN_LENGTH,BUFSIZ-1);
		if (ok >= 0 && verify)
			{
			buff = (char *)OPENSSL_malloc(bufsiz);
			ok = UI_add_verify_string(ui,prompt,ui_flags,buff,
				PW_MIN_LENGTH,BUFSIZ-1, buf);
			}
		if (ok >= 0)
			do {
				ok = UI_process(ui);
			} while (ok < 0 && UI_ctrl(ui, UI_CTRL_IS_REDOABLE, 0, 0, 0));

		if (buff) {
			OPENSSL_cleanse(buff,(unsigned int)bufsiz);
			OPENSSL_free(buff);
		}

		if (ok >= 0)
			res = strlen(buf);
		if (ok == -1) {
			BIO_printf(bio_err, "User interface error\n");
			ERR_print_errors(bio_err);
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
		}
		if (ok == -2) {
			BIO_printf(bio_err,"aborted!\n");
			OPENSSL_cleanse(buf,(unsigned int)bufsiz);
			res = 0;
		}
		UI_free(ui);
		OPENSSL_free(prompt);
	}
	return res;
}

