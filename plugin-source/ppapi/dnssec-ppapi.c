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


/* ========================================================================= */
static
int DictGetValParameters(struct PP_Var dict,
    const char **dom_str, uint32_t *dom_len)
/* ========================================================================= */
{
#define DOM_KEY "domain"
#define DOM_KEY_LEN 6

	struct PP_Var key;
	struct PP_Var val;

	if ((dom_str != NULL) && (dom_len != NULL)) {

		key = g_varInterface->VarFromUtf8(DOM_KEY, DOM_KEY_LEN);
		val = g_varDictInterface->Get(dict, key);
		if (PP_VARTYPE_STRING != val.type) {
			goto fail;
		}

		*dom_str = g_varInterface->VarToUtf8(val, dom_len);

		g_varInterface->Release(val);
		g_varInterface->Release(key);

	}

	return 0;

fail:
	g_varInterface->Release(val);
	g_varInterface->Release(key);
	return -1;
#undef DOM_KEY
#undef DOM_KEY_LEN
}


/* ========================================================================= */
static
void Messaging_HandleMessage(PP_Instance instance, struct PP_Var message)
/* ========================================================================= */
{
#define CMD "command"
#define CMD_LEN 7

//	struct PP_Var keys;
//	struct PP_Var cmd_key;
//	struct PP_Var cmd;
//	uint32_t cmd_len;
//	const char *cmd_str = NULL;
	enum cmd_type type;

	const char *domain;
	uint32_t domain_len;

//	cmd_key = g_varInterface->VarFromUtf8(CMD, CMD_LEN);

	g_varInterface->AddRef(message);

	fprintf(stderr, "_001 %s\n", __func__);
	if (message.type == PP_VARTYPE_DICTIONARY) {
		type = DictGetCmdType(message);
		switch (type) {
		case CMD_INIT:
			fprintf(stderr, "Command INIT %s.\n", __func__);
			break;
		case CMD_DEINIT:
			fprintf(stderr, "Command DEINIT %s.\n", __func__);
			break;
		case CMD_VAL:
			fprintf(stderr, "Command VAL %s.\n", __func__);
			DictGetValParameters(message, &domain, &domain_len);
			for (int i = 0; i < domain_len; ++i) {
				//fputs(domain[i], stderr);
				/*
				 * Calling fputs() causes:
				 * Signal 11 from untrusted code: pc=...
				 */
				fprintf(stderr, "%c", domain[i]);
			}
			fprintf(stderr, "\n");
			break;
		default:
			fprintf(stderr, "Command unknown %s.\n", __func__);
			break;
		}
//		keys = g_varDictInterface->GetKeys(message);
//		fprintf(stderr, "Received %d keys.\n",
//		    g_varArrInterface->GetLength(keys));
//		g_varInterface->Release(keys);
//		cmd = g_varDictInterface->Get(message, cmd_key);
//		fprintf(stderr, "CMD type %d.\n", cmd.type);
//		cmd_str = g_varInterface->VarToUtf8(cmd, &cmd_len);
//		fprintf(stderr, "CMD length %d.\n", cmd_len);
//		for (int i = 0; i < cmd_len; ++i) {
//			fputc(cmd_str[i], stderr);
//		}
//		fputc('\n', stderr);
//		g_varInterface->Release(cmd);
	} else {
		fprintf(stderr, "_003 %s\n", __func__);
	}

	g_varInterface->Release(message);

//	g_varInterface->Release(cmd_key);
}
