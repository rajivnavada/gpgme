#include "gpgme-bridge.h"


// Minimum version of GPGME we'll accept
static const char *GPGME_MIN_VERSION = "1.6.0";
static const int COPY = 1;


int init_gpgme ()
{
    static int initialized = 0;

    // Initialize GPGME if not initialized yet
    if (!initialized)
    {
        const char *version = gpgme_check_version (GPGME_MIN_VERSION);
        initialized = !version ? 0 : 1;
    }

    return initialized;
}


gpgme_ctx_t get_context ()
{
    init_gpgme();

    gpgme_ctx_t ctx = NULL;
    gpgme_error_t err = gpgme_new (&ctx);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        return NULL;

    return ctx;
}


gpgme_key_t get_key (gpgme_ctx_t ctx, const char *fingerprint)
{
    if (!ctx)
        return NULL;

    gpgme_key_t key = NULL;
    gpgme_error_t err = gpgme_get_key (ctx, fingerprint, &key, 0);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        return NULL;

    return key;
}


//----------------------------------------
// PUBLIC API
//----------------------------------------


key_info_t new_key_info ()
{
    return (key_info_t) calloc (1, sizeof (struct key_info));
}


void free_key_info (key_info_t info)
{
    free (info);
    info = NULL;
}


void import_key (key_info_t info, const char *key)
{
    // Variables that MUST be freed before returning
    gpgme_ctx_t ctx = NULL;
    gpgme_data_t key_data = NULL;

    // These should be variables managed by the context
    gpgme_import_result_t import_result = NULL;
    gpgme_import_status_t status = NULL;

    gpgme_error_t err;

    // Let's setup a gpgme context
    ctx = get_context ();
    if (!ctx)
        goto free_resources_and_return;

    // Construct a gpgme_data_t instance from passed in key data
    // NOTE: we ask to copy since we don't want to mess up Go's memory manager
    err = gpgme_data_new_from_mem (&key_data, key, strlen (key), COPY);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        goto free_resources_and_return;

    // Now we get key info
    err = gpgme_op_import (ctx, key_data);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        goto free_resources_and_return;

    import_result = gpgme_op_import_result (ctx);
    if (!import_result || !import_result->imports)
        goto free_resources_and_return;

    // We'll only consider the first result
    status = import_result->imports;

    // Now pull the fingerprint from status and get full description of the key
    get_key_info (info, status->fpr, ctx);

    // Adding this here so that memory can be zeroed in get_key_info
    if (status->status&GPGME_IMPORT_NEW)
        info->is_new = 1;

free_resources_and_return:
    // Release all resources
    if (key_data)
        gpgme_data_release (key_data);
    if (ctx)
        gpgme_release (ctx);
}


// Get information about a key and inserts data into the KEY_INFO.
// If ctx is NULL, a new ctx will be created.
void get_key_info (key_info_t info, const char *fingerprint, gpgme_ctx_t ctx)
{
    if (!fingerprint || !info)
        return;

    int created_ctx = 0;

    if (!ctx)
    {
        ctx = get_context ();
        if (!ctx)
            return;
        created_ctx = 1;
    }

    gpgme_key_t key = get_key (ctx, fingerprint);
    if (!key || !key->subkeys || !key->uids)
        goto free_resources_and_return;

    // NOTE: assuming that the key_info will always be zeroed out
    // Copy the strings
    (void) strncpy (info->fingerprint, key->subkeys->fpr, KEY_FINGERPRINT_LEN);
    (void) strncpy (info->user_name, key->uids->name, KEY_USERNAME_LEN);
    (void) strncpy (info->user_email, key->uids->email, KEY_USEREMAIL_LEN);
    (void) strncpy (info->user_comment, key->uids->comment, KEY_USERCOMMENT_LEN);

    // Copy the expires timestamp
    info->expires = key->subkeys->expires;

    // In this function, is_new will always be set to false
    info->is_new = 0;

free_resources_and_return:
    if (created_ctx && ctx)
    {
        gpgme_release (ctx);
        ctx = NULL;
    }
}


char *encrypt (const char *fingerprint, const char *message)
{
    if (!fingerprint || !message)
        return NULL;

    gpgme_ctx_t ctx = get_context ();
    if (!ctx)
        return NULL;

    // Setup return value for goto
    char *ret = NULL;

    // Variables that need to be freed before exit
    gpgme_data_t data = NULL;
    gpgme_data_t cipher = NULL;

    // Make sure we set the context into ASCII armor mode
    gpgme_set_armor (ctx, 1);

    // Construct a gpgme_data_t instance from data
    // NOTE: we ask to copy since we don't want to mess up Go's memory manager
    gpgme_error_t err = gpgme_data_new_from_mem (&data, message, strlen (message), COPY);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        goto free_resources_and_return;

    // Initialize the cipher storage
    err = gpgme_data_new (&cipher);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        goto free_resources_and_return;

    // Get the key for the recipient
    gpgme_key_t key = get_key (ctx, fingerprint);
    if (!key)
        goto free_resources_and_return;

    gpgme_key_t key_arr[2] = {key, NULL};
    gpgme_encrypt_flags_t flags = GPGME_ENCRYPT_ALWAYS_TRUST | GPGME_ENCRYPT_NO_ENCRYPT_TO | GPGME_ENCRYPT_NO_COMPRESS;

    // Now we can encrypt
    err = gpgme_op_encrypt (ctx, key_arr, flags, data, cipher);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        goto free_resources_and_return;

    // Extract the cipher text from cipher object
    size_t cipher_len = 0;
    ret = gpgme_data_release_and_get_mem (cipher, &cipher_len);
    if (ret && cipher_len > 0)
        ret[cipher_len - 1] = '\0';

    // At this point cipher should already be released and no further release is required
    cipher = NULL;

free_resources_and_return:
    if (cipher)
        gpgme_data_release (cipher);
    if (data)
        gpgme_data_release (data);
    if (ctx)
        gpgme_release (ctx);

    return ret;
}


char *decrypt (const char *encrypted_message)
{
    if (!encrypted_message)
        return NULL;

    gpgme_ctx_t ctx = get_context ();
    if (!ctx)
        return NULL;

    // Setup return value for goto
    char *ret = NULL;

    // Variables that need to be freed before exit
    gpgme_data_t data = NULL;
    gpgme_data_t message = NULL;

    // Construct a gpgme_data_t instance from data
    // NOTE: we ask to copy since we don't want to mess up Go's memory manager
    gpgme_error_t err = gpgme_data_new_from_mem (&data, encrypted_message, strlen (encrypted_message), COPY);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        goto free_resources_and_return;

    // Initialize the cipher storage
    err = gpgme_data_new (&message);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        goto free_resources_and_return;

    // Now we can encrypt
    err = gpgme_op_decrypt (ctx, data, message);
    if (gpg_err_code (err) != GPG_ERR_NO_ERROR)
        goto free_resources_and_return;

    // Extract the cipher text from cipher object
    size_t message_len = 0;
    ret = gpgme_data_release_and_get_mem (message, &message_len);
    if (ret && message_len > 0)
        ret[message_len - 1] = '\0';

    // At this point cipher should already be released and no further release is required
    message = NULL;

free_resources_and_return:
    if (message)
        gpgme_data_release (message);
    if (data)
        gpgme_data_release (data);
    if (ctx)
        gpgme_release (ctx);

    return ret;
}


void free_cipher_text (char *cipher_text)
{
    if (!cipher_text)
        return;

    gpgme_free (cipher_text);
    cipher_text = NULL;
}
