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

#include "dnssec-plug.h"
#include "ppapi/c/pp_bool.h"
#include "ppapi/c/pp_errors.h"
#include "ppapi/c/pp_module.h"
#include "ppapi/c/pp_var.h"
#include "ppapi/c/ppb.h"
#include "ppapi/c/ppb_messaging.h"
#include "ppapi/c/ppb_var.h"
#include "ppapi/c/ppp.h"
#include "ppapi/c/ppp_instance.h"


PP_Module g_module_id;
PPB_GetInterface g_get_browser_interface = NULL;
const PPB_Messaging *g_varMessagingInterface;
const PPB_Var *g_varInterface;


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
PPP_Instance instance_interface = {
	.DidCreate = Instance_DidCreate,
	.DidDestroy = Instance_DidDestroy,
	.DidChangeView = Instance_DidChangeView,
	.DidChangeFocus = Instance_DidChangeFocus,
	.HandleDocumentLoad = Instance_HandleDocumentLoad
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
		return &instance_interface;
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
	/* Create PP_Var containing the message body */
	assert(g_varInterface != NULL);
	struct PP_Var varString =
	    g_varInterface->VarFromUtf8("Hello world!", strlen("Hello world!"));

	/* Post message to the JavaScript layer. */
	g_varMessagingInterface->PostMessage(instance, varString);

	return PP_TRUE;
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
