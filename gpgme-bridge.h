#pragma once

#include <stdlib.h>
#include <string.h>
#include <gpgme.h>
#include <gpg-error.h>


enum {
    KEY_FINGERPRINT_LEN = 40,
    KEY_USERNAME_LEN = 255,
    KEY_USEREMAIL_LEN = 255,
    KEY_USERCOMMENT_LEN = 255
};

// +1 for the terminating 0
typedef struct key_info {
    long int expires;
    char user_name[KEY_USERNAME_LEN+1];
    char user_email[KEY_USEREMAIL_LEN+1];
    char user_comment[KEY_USERCOMMENT_LEN+1];
    char fingerprint[KEY_FINGERPRINT_LEN+1];
    int is_new;
} *key_info_t;

#ifdef __cplusplus
extern "C" {
#endif

    // Returns an instance of key_info
    key_info_t new_key_info ();

    // Frees memory allocation to INFO
    void free_key_info (key_info_t info);

    // Tries to import KEY into the system keychain
    void import_key (key_info_t info, const char *key);

    void get_key_info (key_info_t info, const char *fingerprint, gpgme_ctx_t ctx);

    // Returns encrypted data that MUST be freed by the caller
    char *encrypt (const char *fingerprint, const char *message);

    // Returns decrypted data that MUST be freed by the caller
    char *decrypt (const char *encrypted_message);

#ifdef __cplusplus
}
#endif


