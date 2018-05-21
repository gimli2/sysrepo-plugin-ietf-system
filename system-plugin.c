#include <assert.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <sysrepo.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <time.h>

#include <sys/types.h>
#include <pwd.h>
#include <errno.h>

#include <sys/stat.h>

// Next:
// ? Timezone
// X NTP (software specific)
// X DNS (software specific)
// X RADIUS (software specific)
//   Local users
//   Set datetime RPC
//   Restart and shutdown RPCs (done)

/* prints one value retrieved from sysrepo */
static void
print_value(sr_val_t *value)
{
    syslog(LOG_DEBUG, "Value type = %d", value->type);
    switch (value->type) {
        case SR_CONTAINER_T:
        case SR_CONTAINER_PRESENCE_T:
        case SR_LIST_T:
            /* do not print */
            syslog(LOG_DEBUG, "[list/container]");
            break;
        case SR_STRING_T:
            syslog(LOG_DEBUG, "%s = '%s'", value->xpath, value->data.string_val);
            break;
        case SR_BOOL_T:
            syslog(LOG_DEBUG, "%s = %s", value->xpath, value->data.bool_val ? "true" : "false");
            break;
        case SR_UINT8_T:
            syslog(LOG_DEBUG, "%s = %u", value->xpath, value->data.uint8_val);
            break;
        case SR_UINT16_T:
            syslog(LOG_DEBUG, "%s = %u", value->xpath, value->data.uint16_val);
            break;
        case SR_UINT32_T:
            syslog(LOG_DEBUG, "%s = %u", value->xpath, value->data.uint32_val);
            break;
        case SR_IDENTITYREF_T:
            syslog(LOG_DEBUG, "%s = %s", value->xpath, value->data.identityref_val);
            break;
        case SR_ENUM_T:
            syslog(LOG_DEBUG, "%s = %s", value->xpath, value->data.enum_val);
            break;
        default:
            syslog(LOG_DEBUG, "%s (unprintable)", value->xpath);
            syslog(LOG_DEBUG, "## %s ##", value->data.string_val);
    }
} 

char* 
get_user_homedir(char *username) {
    struct passwd pwd;
    struct passwd *result;
    char *buf;
    size_t bufsize;
    int s;
    bufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (bufsize == -1) bufsize = 16384;  /* Value was indeterminate */
    buf = malloc(bufsize);
    if (buf == NULL) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    s = getpwnam_r(username, &pwd, buf, bufsize, &result);
    if (result == NULL) {
        if (s == 0)
            printf("Not found\n");
        else {
            errno = s;
            perror("getpwnam_r");
        }
        free(buf);
        return NULL;
    }
    //syslog(LOG_DEBUG, "ULU Name: %s; UID: %d, HOME: %s\n", pwd.pw_gecos, (long) pwd.pw_uid, pwd.pw_dir);
    char *ret = strdup(pwd.pw_dir);
    free(buf);
    return ret;
}

// type keydata comment
// ssh-rsa AAAAB... user@machine
static void
update_local_user(sr_session_ctx_t *session, char *username)
{
    syslog(LOG_DEBUG, "------------------------------------------------------");
    syslog(LOG_DEBUG, "ULU username = %s", username);
    
    FILE *fp;
    
    const int LINE_SIZE = 16384;
    const int ALG_SIZE = 64;
    const int COMMENT_SIZE = 512;
    char *outputline = malloc(LINE_SIZE); // algorithm + key data + comment
    
    int rc = SR_ERR_OK;
    char *xpath = malloc(strlen(username) + 1024);
    strcpy(xpath, "/ietf-system:system/authentication/user[name='");
    strcat(xpath, username);
    strcat(xpath, "']/authorized-key/name");
    syslog(LOG_DEBUG, "ULU final XPath: %s", xpath);
    
    char *home = get_user_homedir(username);
    if (home != NULL) {
        syslog(LOG_DEBUG, "ULU homedir: %s", home);
        
        // prepare dir
        char *dstpath = malloc(strlen(home) + 32); // + space for "/.ssh/authorized_keys"
        strcpy(dstpath, home);
        strcat(dstpath, "/.ssh");
        //  TODO:  check if exists
        int status;
        status = mkdir(dstpath, S_IRWXU);
        if (status == 0) {
          syslog(LOG_DEBUG, "ULU .ssh in homedir created");
          // TODO: change ownership
        } else {
            if (errno != EEXIST) {
                syslog(LOG_DEBUG, "ULU .ssh in homedir failed - error: %d", errno);
            }
        }

        strcat(dstpath, "/authorized_keys");
        fp=fopen(dstpath, "w");
        free(dstpath);
        
    } else {
        syslog(LOG_DEBUG, "ULU there is no homedir!");
        // TODO: clear and finish
    }
    
    sr_val_t * keys = NULL;
    size_t cnt = 0;
    rc = sr_get_items(session, xpath, &keys, &cnt);
    if (SR_ERR_NOT_FOUND == rc) {
        syslog(LOG_DEBUG, "NOT FOUND error by retrieving keys: %s", sr_strerror(rc));
    } else if (SR_ERR_OK != rc) {
        syslog(LOG_DEBUG, "GENERIC error by retrieving keys: %s", sr_strerror(rc));
        return;
    } else {
        syslog(LOG_DEBUG, "ULU %d keys recieved", (int)cnt);
        for (size_t i=0; i<cnt; i++) {
            // new xpath for given key - get algorithm
            strcpy(xpath, "/ietf-system:system/authentication/user[name='");
            strcat(xpath, username);
            strcat(xpath, "']/authorized-key[name='");
            strcat(xpath, (&keys[i])->data.string_val);
            strcat(xpath, "']/algorithm");
            syslog(LOG_DEBUG, "ULU key XPath: %s", xpath);
            
            char *algorithm = malloc(ALG_SIZE);
            algorithm[0] = '\0';
            char *comment = malloc(COMMENT_SIZE);
            strcpy(comment, username);
            strcat(comment, "@from-sysrepo");
            char *keydata = malloc(LINE_SIZE - ALG_SIZE - COMMENT_SIZE);
            keydata[0] = '\0';
            
            int valid = 0;
            
            sr_val_t * data = NULL;
            rc = sr_get_item(session, xpath, &data);
            if (SR_ERR_NOT_FOUND == rc) {
                syslog(LOG_DEBUG, "NOT FOUND error by retrieving keydata: %s", sr_strerror(rc));
            } else if (SR_ERR_OK != rc) {
                syslog(LOG_DEBUG, "GENERIC error by retrieving keydata: %s", sr_strerror(rc));
                break;
            } else {
                syslog(LOG_DEBUG, "ULU ALGORITHM");
                print_value(data);
                strcpy(algorithm, data->data.string_val);
                valid++;
            }
            
            // new xpath for given key - get algorithm
            strcpy(xpath, "/ietf-system:system/authentication/user[name='");
            strcat(xpath, username);
            strcat(xpath, "']/authorized-key[name='");
            strcat(xpath, (&keys[i])->data.string_val);
            strcat(xpath, "']/key-data");
            syslog(LOG_DEBUG, "ULU key XPath: %s", xpath);
            
            rc = sr_get_item(session, xpath, &data);
            if (SR_ERR_NOT_FOUND == rc) {
                syslog(LOG_DEBUG, "NOT FOUND error by retrieving keydata: %s", sr_strerror(rc));
            } else if (SR_ERR_OK != rc) {
                syslog(LOG_DEBUG, "GENERIC error by retrieving keydata: %s", sr_strerror(rc));
                break;
            } else {
                syslog(LOG_DEBUG, "ULU KEY-DATA");
                print_value(data);
                strcpy(keydata, data->data.string_val);
                valid++;
            }
            
            strcpy(outputline, algorithm);
            strcat(outputline, " ");
            strcat(outputline, keydata);
            strcat(outputline, " ");
            strcat(outputline, comment);
            strcat(outputline, "\n");
            
            if (valid == 2) {
              syslog(LOG_DEBUG, "FINAL AUTH-KEY LINE: %s", outputline);
              fprintf(fp, outputline);
            } else {
              syslog(LOG_DEBUG, "ULU not all data are corectly read from sysrepo - no line is generated.");
            }
            
            free(algorithm);
            free(keydata);
            free(comment);
        }
    } // end of getting keys
    
    if (fp != NULL) fclose(fp);
     
    syslog(LOG_DEBUG, "------------------------------------------------------");
    free(xpath);
    free(home);
    free(outputline);
}

static void
retrieve_current_config(sr_session_ctx_t *session)
{
    sr_val_t *value = NULL;
    int rc = SR_ERR_OK;

    const char *hostname;

    rc = sr_get_item(session, "/ietf-system:system/hostname", &value);
    if (SR_ERR_NOT_FOUND == rc) {
        hostname = "default";
    } else if (SR_ERR_OK != rc) {
        syslog(LOG_DEBUG, "error by retrieving configuration: %s", sr_strerror(rc));
        return;
    } else {
        assert(value->type == SR_STRING_T);
        hostname = value->data.string_val;
    }

    syslog(LOG_DEBUG, "Setting hostname to %s\n", hostname);
    sethostname(hostname, strlen(hostname));

    if (SR_ERR_OK != rc) {
        sr_free_val(value);
    }
    
    sr_val_t * values = NULL;
    size_t cnt = 0;
    rc = sr_get_items(session, "/ietf-system:system/authentication/user/name", &values, &cnt);
    if (SR_ERR_NOT_FOUND == rc) {
        syslog(LOG_DEBUG, "NOT FOUND error by retrieving configuration: %s", sr_strerror(rc));
    } else if (SR_ERR_OK != rc) {
        syslog(LOG_DEBUG, "GENERIC error by retrieving configuration: %s", sr_strerror(rc));
        return;
    } else {
        syslog(LOG_DEBUG, "%d items recieved", (int)cnt);
        for (size_t i=0; i<cnt; i++) {
            print_value(&values[i]);
            
            update_local_user(session, (&values[i])->data.string_val);
            
        }
    }  
}

static int
module_change_cb(sr_session_ctx_t *session, const char *module_name, sr_notif_event_t event, void *private_ctx)
{
    syslog(LOG_DEBUG, "configuration has changed. Event=%s", event==SR_EV_APPLY?"apply":event==SR_EV_VERIFY?"verify":"unknown");

    retrieve_current_config(session);

    return SR_ERR_OK;
}

#define TIME_BUF_SIZE 64
static char boottime[TIME_BUF_SIZE];

static void get_time_as_string(char (*out)[TIME_BUF_SIZE])
{
    time_t curtime = time(NULL);
    strftime(*out, sizeof(*out), "%Y-%m-%dT%H:%M:%S%z", localtime(&curtime));
    // timebuf ends in +hhmm but should be +hh:mm
    memmove(*out+strlen(*out)-1, *out+strlen(*out)-2, 3);
    (*out)[strlen(*out)-3] = ':';
}

/*static int endsWith(const char *string, const char *suffix)
{
    if (strlen(string) < strlen(suffix))
    {
        return false;
    }
    return !strcmp(string + strlen(string) - strlen(suffix), suffix);
}*/

static int clock_dp_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    char buf[TIME_BUF_SIZE];
    if (!private_ctx)
    {
        get_time_as_string(&buf);
    }
    else
    {
        strcpy(buf, private_ctx);
    }

    sr_val_t *value = calloc(1, sizeof(*value));
    if (!value)
    {
        return SR_ERR_NOMEM;
    }

    value->xpath = strdup(xpath);
    if (!value->xpath)
    {
        free(value);
        return SR_ERR_NOMEM;
    }
    value->type = SR_STRING_T;
    value->data.string_val = strdup(buf);
    if (!value->data.string_val)
    {
        free(value->xpath);
        free(value);
        return SR_ERR_NOMEM;
    }

    *values = value;
    *values_cnt = 1;
    return SR_ERR_OK;
}

enum platform_field
{
    PF_OS_NAME,
    PF_OS_RELEASE,
    PF_OS_VERSION,
    PF_MACHINE
};

static int platform_dp_cb(const char *xpath, sr_val_t **values, size_t *values_cnt, void *private_ctx)
{
    struct utsname data;
    uname(&data);
    const char *str;
    switch((enum platform_field)private_ctx)
    {
    case PF_OS_NAME: str = data.sysname; break;
    case PF_OS_RELEASE: str = data.release; break;
    case PF_OS_VERSION: str = data.version; break;
    case PF_MACHINE: str = data.machine; break;
    default:
        syslog(LOG_DEBUG, "Unrecognized context value for %s", __func__);
        return SR_ERR_NOT_FOUND;
    }


    sr_val_t *value = calloc(1, sizeof(*value));
    if (!value)
    {
        return SR_ERR_NOMEM;
    }

    value->xpath = strdup(xpath);
    if (!value->xpath)
    {
        free(value);
        return SR_ERR_NOMEM;
    }
    value->type = SR_STRING_T;
    value->data.string_val = strdup(str);
    if (!value->data.string_val)
    {
        free(value->xpath);
        free(value);
        return SR_ERR_NOMEM;
    }

    *values = value;
    *values_cnt = 1;
    return SR_ERR_OK;
}


int exec_rpc_cb(const char *xpath, const sr_val_t *input, const size_t input_cnt, sr_val_t **output, size_t *output_cnt, void *private_ctx)
{
    system(private_ctx);
    return SR_ERR_OK;
}

/* Registers for providing of operational data under given xpath. */  
/* Registers for providing of operational data under given xpath. */  
int
sr_plugin_init_cb(sr_session_ctx_t *session, void **private_ctx)
{
    sr_subscription_ctx_t *subscription = NULL;
    int rc = SR_ERR_OK;

    rc = sr_module_change_subscribe(session, "ietf-system", module_change_cb, NULL, 0, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) {
        goto error;
    }

    get_time_as_string(&boottime);

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/clock/current-datetime", clock_dp_cb, NULL, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/clock/boot-datetime", clock_dp_cb, boottime, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/platform/os-name", platform_dp_cb, (void*)PF_OS_NAME, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/platform/os-release", platform_dp_cb, (void*)PF_OS_RELEASE, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/platform/os-version", platform_dp_cb, (void*)PF_OS_VERSION, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_dp_get_items_subscribe(session, "/ietf-system:system-state/platform/machine", platform_dp_cb, (void*)PF_MACHINE, SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    rc = sr_rpc_subscribe(session, "/ietf-system:system-restart", exec_rpc_cb, "shutdown -r now", SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;
    rc = sr_rpc_subscribe(session, "/ietf-system:system-shutdown", exec_rpc_cb, "shutdown -h now", SR_SUBSCR_CTX_REUSE, &subscription);
    if (SR_ERR_OK != rc) goto error;

    syslog(LOG_DEBUG, "plugin initialized successfully");

    retrieve_current_config(session);

    /* set subscription as our private context */
    *private_ctx = subscription;

    return SR_ERR_OK;

error:
    syslog(LOG_ERR, "plugin initialization failed: %s", sr_strerror(rc));
    sr_unsubscribe(session, subscription);
    return rc;
}

void
sr_plugin_cleanup_cb(sr_session_ctx_t *session, void *private_ctx)
{
    /* subscription was set as our private context */
    sr_unsubscribe(session, private_ctx);

    syslog(LOG_DEBUG, "plugin cleanup finished");
}

