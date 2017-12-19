/*
 * If not stated otherwise in this file or this component's Licenses.txt file the
 * following copyright and licenses apply:
 *
 * Copyright 2015 RDK Management
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

/**********************************************************************
   Copyright [2014] [Cisco Systems, Inc.]
 
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
 
       http://www.apache.org/licenses/LICENSE-2.0
 
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
**********************************************************************/

/*********************************************************************************

    description:

        This is the main SNMP Plugin function of CCSP MIB helper.

        The implementation of functions:

        *   init_ccsp_snmp_plugin
        *   remove_ccsp_snmp_plugin

  ------------------------------------------------------------------------------

    revision:

        05/01/2012    initial revision.

**********************************************************************************/
#include "ansc_platform.h"
#include "ansc_load_library.h"
#include "ansc_xml_dom_parser_interface.h"
#include "ansc_xml_dom_parser_external_api.h"
#include "ansc_xml_dom_parser_status.h"
#include "CcspSnmpPlugin.h"
#include "ccsp_mib_helper.h"
#include "cosa_api.h"

#ifdef INCLUDE_BREAKPAD
#include "breakpad_wrapper.h"
#endif /* INCLUDE_BREAKPAD */

#ifdef RDKB_MIB
#define  CCSP_MIB_MAPPING_LIST_FILE        "CcspRDKBMibList.xml"
#else
#define  CCSP_MIB_MAPPING_LIST_FILE        "CcspMibList.xml"
#endif

#define DEBUG_INI_NAME  "/etc/debug.ini"

#define  CCSP_MIB_FILE_NODE_NAME           "mibFile"

#define NELEMS(arr)                         (sizeof(arr) / sizeof((arr)[0]))

PCCSP_MIB_HELPER_OBJECT                    g_CcspMibHelper = NULL;

static void
set_debug_level(void)
{
    char *ccspDbg;
    int i;
    struct {
        char *name;
        int level;
    } levelTab[] = {
        {"debug",       CCSP_TRACE_LEVEL_DEBUG, },
        {"info",        CCSP_TRACE_LEVEL_INFO, },
        {"notice",      CCSP_TRACE_LEVEL_NOTICE, },
        {"warning",     CCSP_TRACE_LEVEL_WARNING, },
        {"error",       CCSP_TRACE_LEVEL_ERROR, },
        {"critical",    CCSP_TRACE_LEVEL_CRITICAL, },
        {"alert",       CCSP_TRACE_LEVEL_ALERT, },
        {"emergency",   CCSP_TRACE_LEVEL_EMERGENCY, },
    };

            pComponentName = "CCSP_SNMNP_Plugin";

    ccspDbg = getenv("CCSPDBG");
    if (!ccspDbg)
        return;

    for (i = 0; i < NELEMS(levelTab); i++)
    {
        if (AnscEqualString(ccspDbg, levelTab[i].name, TRUE))
        {
            AnscSetTraceLevel(levelTab[i].level);
            //pComponentName = "CCSP_SNMNP_Plugin";

            AnscTraceWarning(("setting debug level to \"%s\"\n", levelTab[i].name));
            break;
        }
    }

    return;
}

void
init_ccsp_snmp_plugin(void)
{
    ANSC_HANDLE                     pFileHandle        = NULL;
    char*                           pXMLContent        = NULL;
    ULONG                           uXMLLength         = 0;
    ULONG                           uFileLength        = 0;
    ULONG                           uBufferSize        = 0;
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    char                            buffer[64]         = { 0 };
    ULONG                           uLength            = 63;
	PCHAR							pBackBuffer        = NULL;

    set_debug_level();

#ifdef FEATURE_SUPPORT_RDKLOG
    RDK_LOGGER_INIT();
#endif

#ifdef INCLUDE_BREAKPAD
	breakpad_ExceptionHandler( );
#endif /* INCLUDE_BREAKPAD */

	/* init the COSA debus */
	if (!Cosa_Init())
    {
        AnscTraceError(("%s: Cosa_Init error\n", __FUNCTION__));
        return;
    }

	printf("****snmp rdklogger init %s\n",pComponentName);

    CcspTraceWarning(("SNMP:snmp initialzed!\n"));

	g_CcspMibHelper = (PCCSP_MIB_HELPER_OBJECT)CcspCreateMibHelper();

	if( g_CcspMibHelper == NULL)
	{
		return;
	}

	/* load the MIB List XML file */
    pFileHandle =
        AnscOpenFile
        (
            CCSP_MIB_MAPPING_LIST_FILE,
            ANSC_FILE_O_BINARY | ANSC_FILE_O_RDONLY,
            ANSC_FILE_S_IREAD
        );

    if( pFileHandle == NULL)
    {
        AnscTraceWarning(("Failed to load the file : '%s'\n", CCSP_MIB_MAPPING_LIST_FILE));

        return;
    }

    uFileLength = AnscGetFileSize( pFileHandle);

    pXMLContent = (char*)AnscAllocateMemory( uFileLength + 8);

    if( pXMLContent == NULL)
    {
		AnscCloseFile(pFileHandle);
        return;
    }

    uBufferSize = uFileLength + 8;

    if( AnscReadFile( pFileHandle, pXMLContent, &uBufferSize) != ANSC_STATUS_SUCCESS)
    {
        AnscFreeMemory(pXMLContent);
		AnscCloseFile(pFileHandle);

		return;
    }

	/* close the file handle */
    AnscCloseFile(pFileHandle);

	/* parse the XML file */
	pBackBuffer = pXMLContent;

    pRootNode = (PANSC_XML_DOM_NODE_OBJECT)
        AnscXmlDomParseString((ANSC_HANDLE)NULL, (PCHAR*)&pBackBuffer, uBufferSize);
	printf("Test XML : %s\n", pRootNode->Name);
    AnscFreeMemory(pXMLContent);

    if( pRootNode == NULL)
    {
        AnscTraceWarning(("Failed to Ccsp MIB List XML file.\n"));

        return;
    }

	/* go through MIB files one by one */
    pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetHeadChild(pRootNode);

    while( pChildNode != NULL)
    {
		AnscZeroMemory(buffer, 64);
		uLength = 63;

		if(AnscEqualString(pChildNode->GetName(pChildNode),CCSP_MIB_FILE_NODE_NAME, TRUE))
        {
            pChildNode->GetDataString(pChildNode, NULL, buffer, &uLength);

            if ( !g_CcspMibHelper->LoadCcspMibFile(g_CcspMibHelper, buffer))
            {
                AnscTraceWarning(("Failed to load Ccsp Mib file: %s\n", buffer));
            }
        }
		else
		{
			AnscTraceWarning(("Unknown XML node name: %s\n", pChildNode->GetName(pChildNode)));
		}

        /* goto next one */
        pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetNextChild(pRootNode, pChildNode);
    }

	/* clear the XML node handle */
    if( pRootNode != NULL)
    {
        pRootNode->Remove(pRootNode);
    }

}

void
remove_ccsp_snmp_plugin(void)
{
	if( g_CcspMibHelper)
	{
		g_CcspMibHelper->Remove(g_CcspMibHelper);
		g_CcspMibHelper = NULL;
	}

	/* exit the COSA debus */
	Cosa_Shutdown();
}

