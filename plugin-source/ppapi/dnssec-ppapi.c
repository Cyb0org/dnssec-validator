/* ***** BEGIN LICENSE BLOCK *****
Copyright 2013 CZ.NIC, z.s.p.o.
File: DANE/TLSA library
Authors: Martin Straka <martin.straka@nic.cz>
         Karel Slany <karel.slany@nic.cz>

This file is part of TLSA Validator 2 Add-on.

TLSA Validator 2 Add-on is free software: you can redistribute it and/or
modify it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or (at your
option) any later version.

TLSA Validator 2.Add-on is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
more details.

You should have received a copy of the GNU General Public License along with
TLSA Validator 2 Add-on.  If not, see <http://www.gnu.org/licenses/>.

Additional permission under GNU GPL version 3 section 7

If you modify this Program, or any covered work, by linking or
combining it with OpenSSL (or a modified version of that library),
containing parts covered by the terms of The OpenSSL Project, the
licensors of this Program grant you additional permission to convey
the resulting work. Corresponding Source for a non-source form of
such a combination shall include the source code for the parts of
OpenSSL used as well as that of the covered work.
***** END LICENSE BLOCK ***** */


#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "dnssec-plug.h"
#include "ppapi/c/pp_bool.h"
#include "ppapi/c/pp_errors.h"
#include "ppapi/c/pp_module.h"
#include "ppapi/c/pp_var.h"
#include "ppapi/c/ppb.h"
#include "ppapi/c/ppb_messaging.h"
#include "ppapi/c/ppb_var.h"
#include "ppapi/c/ppb_var_array.h"
#include "ppapi/c/ppb_var_dictionary.h"
#include "ppapi/c/ppp.h"
#include "ppapi/c/ppp_instance.h"
#include "ppapi/c/ppp_messaging.h"


PP_Module g_module_id;
PPB_GetInterface g_get_browser_interface = NULL;

const PPB_Messaging *g_varMessagingInterface = NULL;
const PPB_Var *g_varInterface = NULL;
const PPB_VarArray *g_varArrInterface = NULL;
const PPB_VarDictionary *g_varDictInterface = NULL;


#ifdef __cplusplus
extern "C" {
#endif


/*!
 * @brief Called when module is loaded.
 */
PP_EXPORT
int32_t PPP_InitializeModule(PP_Module module_id,
    PPB_GetInterface get_browser_interface);


/*!
 * @brief Called on unload?
 */
PP_EXPORT
void PPP_ShutdownModule();


/*!
 * @brief Exports interfaces.
 */
PP_EXPORT
const void * PPP_GetInterface(const char *interface_name);


static
PP_Bool Instance_DidCreate(PP_Instance instance, uint32_t argc,
    const char *argn[], const char *argv[]);


static
void Instance_DidDestroy(PP_Instance instance);


static
void Instance_DidChangeView(PP_Instance pp_instance, PP_Resource view);


static
void Instance_DidChangeFocus(PP_Instance pp_instance, PP_Bool has_focus);


static
PP_Bool Instance_HandleDocumentLoad(PP_Instance pp_instance,
    PP_Resource pp_url_loader);


/*!
 * @brief PPAPI instance interface structure.
 */
static
PPP_Instance instance_interface = {
	.DidCreate = Instance_DidCreate,
	.DidDestroy = Instance_DidDestroy,
	.DidChangeView = Instance_DidChangeView,
	.DidChangeFocus = Instance_DidChangeFocus,
	.HandleDocumentLoad = Instance_HandleDocumentLoad
};


static
void Messaging_HandleMessage(PP_Instance instance, struct PP_Var message);


/*!
 * @brief PPAPI messaging inetrface structure.
 */
static
PPP_Messaging messaging_interface = {
	.HandleMessage = Messaging_HandleMessage
};


struct val_data {
	char *domain;
	uint16_t options;
	char *ipresolver;
	char *ipbrowser;
};


#define val_data_init(vd) \
	do { \
		(vd)->domain = NULL; \
		(vd)->options = 0; \
		(vd)->ipresolver = NULL; \
		(vd)->ipbrowser = NULL; \
	} while(0)


#define val_data_deep_free(vd) \
	do { \
		assert(NULL != (vd)); \
		if (NULL != (vd)->domain) { \
			free((vd)->domain); \
		} \
		if (NULL != (vd)->ipresolver) { \
			free((vd)->ipresolver); \
		} \
		if (NULL != (vd)->ipbrowser) { \
			free((vd)->ipbrowser); \
		} \
		free(vd); \
	} while(0)


/*!
 * @brief Returns newly allocated structure.
 *
 * @note The caller is responsible for freeing the returned value.
 */
static
struct val_data * DictGetValParameters(struct PP_Var dict)
    __attribute__((warn_unused_result));


#ifdef __cplusplus
} /* extern "C" */
#endif


/* ========================================================================= */
/*
 * Called when module is loaded.
 */
PP_EXPORT
int32_t PPP_InitializeModule(PP_Module module_id,
    PPB_GetInterface get_browser_interface)
/* ========================================================================= */
{
	/* Save the global module information for later. */
	g_module_id = module_id;
	g_get_browser_interface = get_browser_interface;

	/* Initializing global pointers */
	g_varMessagingInterface = get_browser_interface(
	    PPB_MESSAGING_INTERFACE);
	g_varInterface = get_browser_interface(PPB_VAR_INTERFACE);
	g_varArrInterface = get_browser_interface(PPB_VAR_ARRAY_INTERFACE);
	g_varDictInterface =
	    get_browser_interface(PPB_VAR_DICTIONARY_INTERFACE);

	fprintf(stderr, "_001 %s\n", __func__);

	return PP_OK;
}


/* ========================================================================= */
/*
 * Called on unload?
 */
PP_EXPORT
void PPP_ShutdownModule()
/* ========================================================================= */
{
}


/* ========================================================================= */
/*
 * Exports interfaces.
 */
PP_EXPORT
const void * PPP_GetInterface(const char *interface_name)
/* ========================================================================= */
{
	assert(interface_name != NULL);

	if (strcmp(interface_name, PPP_INSTANCE_INTERFACE) == 0) {
		fprintf(stderr, "_001 %s\n", __func__);
		return &instance_interface;
	}
	if (strcmp(interface_name, PPP_MESSAGING_INTERFACE) == 0) {
		fprintf(stderr, "_002 %s\n", __func__);
		return &messaging_interface;
	}

	return NULL;
}


/* ========================================================================= */
/* Static function definitions below here. */
/* ========================================================================= */


/* ========================================================================= */
static
PP_Bool Instance_DidCreate(PP_Instance instance, uint32_t argc,
    const char *argn[], const char *argv[])
/* ========================================================================= */
{
#define STR "Hello world!"

	/* Create PP_Var containing the message body */
	assert(g_varInterface != NULL);
	struct PP_Var varString =
	    g_varInterface->VarFromUtf8(STR, strlen(STR));

	/* Post message to the JavaScript layer. */
	g_varMessagingInterface->PostMessage(instance, varString);

	return PP_TRUE;
#undef STR
}


/* ========================================================================= */
static
void Instance_DidDestroy(PP_Instance instance)
/* ========================================================================= */
{
}


/* ========================================================================= */
static
void Instance_DidChangeView(PP_Instance pp_instance, PP_Resource view)
/* ========================================================================= */
{
}


/* ========================================================================= */
static
void Instance_DidChangeFocus(PP_Instance pp_instance, PP_Bool has_focus)
/* ========================================================================= */
{
}


/* ========================================================================= */
static
PP_Bool Instance_HandleDocumentLoad(PP_Instance pp_instance,
    PP_Resource pp_url_loader)
/* ========================================================================= */
{
	return PP_FALSE;
}


#define CMD_INIT_STR "initialise"
#define CMD_INIT_LEN 10
#define CMD_DEINIT_STR "deinitialise"
#define CMD_DEINIT_LEN 12
#define CMD_VAL_STR "validate"
#define CMD_VAL_LEN 8

enum cmd_type {
	CMD_UNKNOWN = 0,
	CMD_INIT,
	CMD_DEINIT,
	CMD_VAL
};



/* ========================================================================= */
static
enum cmd_type DictGetCmdType(struct PP_Var dict)
/* ========================================================================= */
{
#define CMD_KEY "command"
#define CMD_KEY_LEN 7

	struct PP_Var cmd_key;
	struct PP_Var cmd;
	uint32_t cmd_len;
	const char *cmd_str = NULL;
	enum cmd_type ret = CMD_UNKNOWN;

	cmd_key = g_varInterface->VarFromUtf8(CMD_KEY, CMD_KEY_LEN);

	cmd = g_varDictInterface->Get(dict, cmd_key);
	assert(PP_VARTYPE_STRING == cmd.type);
	cmd_str = g_varInterface->VarToUtf8(cmd, &cmd_len);

	if ((CMD_INIT_LEN == cmd_len) &&
	    (memcmp(CMD_INIT_STR, cmd_str, CMD_INIT_LEN) == 0)) {
		ret = CMD_INIT;
	} else
	if ((CMD_DEINIT_LEN == cmd_len) &&
	    (memcmp(CMD_DEINIT_STR, cmd_str, CMD_DEINIT_LEN) == 0)) {
		ret = CMD_DEINIT;
	} else
	if ((CMD_VAL_LEN == cmd_len) &&
	    (memcmp(CMD_VAL_STR, cmd_str, CMD_VAL_LEN) == 0)) {
		ret = CMD_VAL;
	}

	g_varInterface->Release(cmd);

	g_varInterface->Release(cmd_key); // Key cannot be released before cmd.

	return ret;

#undef CMD_KEY
#undef CMD_KEY_LEN
}


//struct val_data {
//	char *domain;
//	uint16_t options;
//	char *ipresolver;
//	char *ipbrowser;
//};


/* ========================================================================= */
static
struct val_data * DictGetValParameters(struct PP_Var dict)
/* ========================================================================= */
{
#define DOM_KEY "domain"
#define DOM_KEY_LEN 6
#define OPT_KEY "options"
#define OPT_KEY_LEN 7
#define RES_KEY "ipresolver"
#define RES_KEY_LEN 10
#define BROW_KEY "ipbrowser"
#define BROW_KEY_LEN 9

	struct val_data *ret = NULL;
	const char *str;
	uint32_t str_len;
	struct PP_Var key;
	struct PP_Var val;

	ret = malloc(sizeof(struct val_data));
	if (NULL == ret) {
		goto fail;
	}

	/* Domain name. */
	key = g_varInterface->VarFromUtf8(DOM_KEY, DOM_KEY_LEN);
	val = g_varDictInterface->Get(dict, key);
	if (PP_VARTYPE_STRING != val.type) {
		goto fail;
	}

	str = g_varInterface->VarToUtf8(val, &str_len);

	ret->domain = malloc(str_len + 1);
	if (NULL == ret->domain) {
		goto fail;
	}
	memcpy(ret->domain, str, str_len);
	ret->domain[str_len] = '\0';

	g_varInterface->Release(val);
	g_varInterface->Release(key);

	/* Options. */
	key = g_varInterface->VarFromUtf8(OPT_KEY, OPT_KEY_LEN);
	val = g_varDictInterface->Get(dict, key);
	if (PP_VARTYPE_INT32 != val.type) {
		goto fail;
	}

	ret->options = val.value.as_int;

	g_varInterface->Release(val);
	g_varInterface->Release(key);

	/* Resolver. */
	key = g_varInterface->VarFromUtf8(RES_KEY, RES_KEY_LEN);
	val = g_varDictInterface->Get(dict, key);
	if (PP_VARTYPE_STRING != val.type) {
		goto fail;
	}

	str = g_varInterface->VarToUtf8(val, &str_len);

	ret->ipresolver = malloc(str_len + 1);
	if (NULL == ret->ipresolver) {
		goto fail;
	}
	memcpy(ret->ipresolver, str, str_len);
	ret->ipresolver[str_len] = '\0';

	g_varInterface->Release(val);
	g_varInterface->Release(key);

	/* Browser. */
	/* Resolver. */
	key = g_varInterface->VarFromUtf8(BROW_KEY, BROW_KEY_LEN);
	val = g_varDictInterface->Get(dict, key);
	if (PP_VARTYPE_STRING != val.type) {
		goto fail;
	}

	str = g_varInterface->VarToUtf8(val, &str_len);

	ret->ipbrowser = malloc(str_len + 1);
	if (NULL == ret->ipbrowser) {
		goto fail;
	}
	memcpy(ret->ipbrowser, str, str_len);
	ret->ipbrowser[str_len] = '\0';

	g_varInterface->Release(val);
	g_varInterface->Release(key);

	return ret;

fail:
 	if (NULL != ret) {
		val_data_deep_free(ret);
	}
	g_varInterface->Release(val);
	g_varInterface->Release(key);
	return NULL;
#undef DOM_KEY
#undef DOM_KEY_LEN
#undef OPT_KEY
#undef OPT_KEY_LEN
#undef RES_KEY
#undef RES_KEY_LEN
#undef BROW_KEY
#undef BROW_KEY_LEN
}


/* ========================================================================= */
static
void Messaging_HandleMessage(PP_Instance instance, struct PP_Var message)
/* ========================================================================= */
{
#define CMD "command"
#define CMD_LEN 7

	enum cmd_type type;
	struct val_data *vd = NULL;
	int val_ret;
	char *ipvalidator; /* Don't try to free. */

	g_varInterface->AddRef(message);

	fprintf(stderr, "_001 %s\n", __func__);
	if (message.type == PP_VARTYPE_DICTIONARY) {
		type = DictGetCmdType(message);
		switch (type) {
		case CMD_INIT:
			fprintf(stderr, "Command INIT %s.\n", __func__);
			dnssec_validation_init();
			break;
		case CMD_DEINIT:
			fprintf(stderr, "Command DEINIT %s.\n", __func__);
			dnssec_validation_deinit();
			break;
		case CMD_VAL:
			fprintf(stderr, "Command VAL %s.\n", __func__);
			vd = DictGetValParameters(message);
			if (NULL != vd) {
				fprintf(stderr, "%s %d '%s' '%s'\n",
				    vd->domain, vd->options, vd->ipresolver,
				    vd->ipbrowser);
				val_ret = dnssec_validate(vd->domain,
				    vd->options, vd->ipresolver, vd->ipbrowser,
				    &ipvalidator);
				fprintf(stderr, "Validation return %d.\n",
				    val_ret);
				val_data_deep_free(vd); vd = NULL;
			} else {
			}
			break;
		default:
			fprintf(stderr, "Command unknown %s.\n", __func__);
			break;
		}
	} else {
		fprintf(stderr, "_003 %s\n", __func__);
	}

	g_varInterface->Release(message);
}
