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

        This is the implementation of object "CCSP_MIB_HELPER_OBJECT"

        The implementation of local functions:
        *   CcspMibHelperRemove
		*   CcspMibHelperLoadCcspMibFile

        The implementation of function:
        *   CcspCreateMibHelper

  ------------------------------------------------------------------------------

    revision:

        05/01/2012    initial revision.

**********************************************************************************/
#include "ansc_platform.h"
#include "ansc_load_library.h"
#include "ansc_xml_dom_parser_interface.h"
#include "ansc_xml_dom_parser_external_api.h"
#include "ansc_xml_dom_parser_status.h"
#include "ccsp_mib_helper.h"
#include "ccsp_scalar_helper.h"
#include "ccsp_table_helper.h"

#define CCSP_XML_NODE_library                          "library"
#define CCSP_XML_NODE_scalarGroups                     "scalarGroups"
#define CCSP_XML_NODE_scalarGroup                      "scalarGroup"
#define CCSP_XML_NODE_mibTables                        "mibTables"
#define CCSP_XML_NODE_mibTable                         "mibTable"

/**********************************************************************

    prototype:

    BOOL
    CcspMibHelperLoadCcspMibFile
        (
			ANSC_HANDLE				hThisObject,
			char*					pFileName
        );

    description:

        This function is called to load information of a MIB mapping file;

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

				char*					pFileName
				The MIB mapping file name;

	return:     Succeeded or failed

**********************************************************************/
BOOL
CcspMibHelperLoadCcspMibFile
	(
			ANSC_HANDLE				hThisObject,
			char*					pFileName
	)
{
	PCCSP_MIB_HELPER_OBJECT			pThisObject        = (PCCSP_MIB_HELPER_OBJECT)hThisObject;
    ANSC_HANDLE                     pFileHandle        = NULL;
    char*                           pXMLContent        = NULL;
    ULONG                           uXMLLength         = 0;
    ULONG                           uFileLength        = 0;
    ULONG                           uBufferSize        = 0;
    PANSC_XML_DOM_NODE_OBJECT       pRootNode          = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pListNode          = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    PANSC_XML_DOM_NODE_OBJECT       pChildNode         = (PANSC_XML_DOM_NODE_OBJECT)NULL;
    char                            buffer[64]         = { 0 };
    ULONG                           uLength            = 63;
	PCHAR							pBackBuffer        = NULL;
	ANSC_HANDLE						hLibrary           = NULL;
	PCCSP_SCALAR_HELPER_OBJECT      pScalarObj         = (PCCSP_SCALAR_HELPER_OBJECT)NULL;
	PCCSP_TABLE_HELPER_OBJECT       pTableObj          = (PCCSP_TABLE_HELPER_OBJECT)NULL;

	if( pFileName == NULL)
	{
		return FALSE;
	}

	/* load the MIB List XML file */
    pFileHandle =
        AnscOpenFile
        (
            pFileName,
            ANSC_FILE_O_BINARY | ANSC_FILE_O_RDONLY,
            ANSC_FILE_S_IREAD
        );

    if( pFileHandle == NULL)
    {
        AnscTraceWarning(("Failed to load the file : '%s'\n", pFileName));

        return FALSE;
    }

    uFileLength = AnscGetFileSize( pFileHandle);

    pXMLContent = (char*)AnscAllocateMemory( uFileLength + 8);

    if( pXMLContent == NULL)
    {
		AnscCloseFile(pFileHandle);
        return FALSE;
    }

    uBufferSize = uFileLength + 8;

    if( AnscReadFile( pFileHandle, pXMLContent, &uBufferSize) != ANSC_STATUS_SUCCESS)
    {
        AnscFreeMemory(pXMLContent);
		AnscCloseFile(pFileHandle);

		return FALSE;
    }

	/* close the file handle */
     AnscCloseFile(pFileHandle);

	 /* parse the XML file */
	pBackBuffer = pXMLContent;

    pRootNode = (PANSC_XML_DOM_NODE_OBJECT)
        AnscXmlDomParseString((ANSC_HANDLE)NULL, (PCHAR*)&pBackBuffer, uBufferSize);

    AnscFreeMemory(pXMLContent);

    if( pRootNode == NULL)
    {
        AnscTraceWarning(("Failed to Ccsp MIB List XML file.\n"));

        return FALSE;
    }

	/* Load the library if exists */
	pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_NODE_library);

	if( pChildNode != NULL)
	{
		if( ANSC_STATUS_SUCCESS == pChildNode->GetDataString(pChildNode, NULL, buffer, &uLength))
		{
			/* load library */
			hLibrary = (void*)AnscLoadLibrary(buffer);

			if( hLibrary != NULL)
			{
				pThisObject->hLibArray[pThisObject->uLibCount] = hLibrary;
				pThisObject->uLibCount++;
			}
		}
	}

	/* load scalar group mibs */
	pListNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_NODE_scalarGroups);

	if( pListNode != NULL)
	{
		  pChildNode  = (PANSC_XML_DOM_NODE_OBJECT)pListNode->GetHeadChild(pListNode);

		  while(pChildNode != NULL)
		  {
			  pScalarObj = (PCCSP_SCALAR_HELPER_OBJECT)CcspCreateScalarHelper();

			  if( pScalarObj != NULL)
			  {
				  pScalarObj->LoadMibs(pScalarObj, pChildNode, hLibrary);

				  /* add it to the queue */
   				  AnscQueuePushEntry(&pThisObject->sScalarQueue, &pScalarObj->Linkage);

			  }

              pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pListNode->GetNextChild(pListNode, pChildNode);
		  }
	}

	/* load table mibs */
	pListNode = (PANSC_XML_DOM_NODE_OBJECT)pRootNode->GetChildByName(pRootNode, CCSP_XML_NODE_mibTables);

	if( pListNode != NULL)
	{
		  pChildNode  = (PANSC_XML_DOM_NODE_OBJECT)pListNode->GetHeadChild(pListNode);

		  while(pChildNode != NULL)
		  {
			  pTableObj = (PCCSP_TABLE_HELPER_OBJECT)CcspCreateTableHelper();

			  if( pTableObj != NULL)
			  {
				  pTableObj->LoadMibs(pTableObj, pChildNode, hLibrary);

				  /* add it to the queue */
   				  AnscQueuePushEntry(&pThisObject->sTableQueue, &pTableObj->Linkage);

			  }

              pChildNode = (PANSC_XML_DOM_NODE_OBJECT)pListNode->GetNextChild(pListNode, pChildNode);
		  }
	}

	/* clear the XML node handle */
    if( pRootNode != NULL)
    {
        pRootNode->Remove(pRootNode);
    }

	return TRUE;
}
/**********************************************************************

    prototype:

    void
    CcspMibHelperRemove
        (
			ANSC_HANDLE				hThisObject
        );

    description:

        This function is called to remove the memory of object "CCSP_MIB_HELPER_OBJECT".

    argument:   ANSC_HANDLE				hThisObject
	            The handle of the object;

	return:     None

**********************************************************************/
void
CcspMibHelperRemove
	(
			ANSC_HANDLE				hThisObject
	)
{
	PCCSP_MIB_HELPER_OBJECT			pThisObject  = (PCCSP_MIB_HELPER_OBJECT)hThisObject;
    PSINGLE_LINK_ENTRY              pSLinkEntry  = (PSINGLE_LINK_ENTRY       )NULL;
	PCCSP_SCALAR_HELPER_OBJECT      pScalarObj   = (PCCSP_SCALAR_HELPER_OBJECT)NULL;
	ANSC_HANDLE						hLibrary     = (ANSC_HANDLE)NULL;
	PCCSP_TABLE_HELPER_OBJECT       pTableObj    = (PCCSP_TABLE_HELPER_OBJECT)NULL;
	int                             i            = 0;

	if( pThisObject == NULL)
	{
		return;
	}

	/* release all the libraries */
	for( i = 0; i < pThisObject->uLibCount; i ++)
	{
		if( pThisObject->hLibArray[i] != NULL)
		{
			hLibrary = pThisObject->hLibArray[i];
			AnscFreeLibrary((ANSC_HANDLE)hLibrary);
			pThisObject->hLibArray[i] = NULL;
		}		
	}

	/* release the queues */
    pSLinkEntry = AnscQueuePopEntry(&pThisObject->sScalarQueue);

    while ( pSLinkEntry )
    {
        pScalarObj       = ACCESS_CCSP_SCALAR_HELPER_OBJECT(pSLinkEntry);
        pSLinkEntry     = AnscQueuePopEntry(&pThisObject->sScalarQueue);

		pScalarObj->Remove(pScalarObj);
    }

   pSLinkEntry = AnscQueuePopEntry(&pThisObject->sTableQueue);

    while ( pSLinkEntry )
    {
        pTableObj       = ACCESS_CCSP_TABLE_HELPER_OBJECT(pSLinkEntry);
        pSLinkEntry     = AnscQueuePopEntry(&pThisObject->sTableQueue);

		pTableObj->Remove(pTableObj);
    }

	/* remove itself */
	AnscFreeMemory(hThisObject);
}
/**********************************************************************

    prototype:

    void*
    CcspCreateMibHelper
        (
        );

    description:

        This function is called to create an object of "CCSP_MIB_HELPER_OBJECT".

    argument:   None

	return:     The handle of the object;

**********************************************************************/
void*
CcspCreateMibHelper
	(
	)
{
	PCCSP_MIB_HELPER_OBJECT			pThisObject        = NULL;

	pThisObject = (PCCSP_MIB_HELPER_OBJECT)AnscAllocateMemory(sizeof(CCSP_MIB_HELPER_OBJECT));

	if( pThisObject == NULL)
	{
		return NULL;
	}

	AnscZeroMemory((void*)pThisObject, sizeof(CCSP_MIB_HELPER_OBJECT));

	pThisObject->uLibCount  = 0;

	pThisObject->LoadCcspMibFile	= CcspMibHelperLoadCcspMibFile;
	pThisObject->Remove             = CcspMibHelperRemove;

    /* init the queues */
    AnscQueueInitializeHeader(&pThisObject->sScalarQueue);
    AnscQueueInitializeHeader(&pThisObject->sTableQueue);

	return (void*)pThisObject;
}

