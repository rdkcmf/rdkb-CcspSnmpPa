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


#include "cosa_api.h"
#include "ccsp_snmp_common.h"
#include "safec_lib_common.h"



/* 
 * gets a string from the model 
 * return 0 if OK and -1 on error 
 */
int get_dm_value(const char *param, char *val, size_t len)
{
    char*                   ppDestComponentName= NULL;
    char*                   ppDestPath =NULL;
    int                     size = 0;
    parameterValStruct_t ** parameterVal = NULL;
    int                     iReturn = 0;
    
    //check for NULL string
    if( NULL == param || val == NULL)
        return -1;
    
    //Get Destination component 
    if(!Cosa_FindDestComp((char *)param, &ppDestComponentName, &ppDestPath)){
        AnscTraceWarning(("Failed to find the CCSP component who supports '%s'\n", param));
        goto get_negative_result;
    }
    
    //Get Parameter Values from ccsp
    iReturn =Cosa_GetParamValues(ppDestComponentName,
             ppDestPath,
             (char **)&param,
             1,
             &size ,
             &parameterVal);
    
     if (!iReturn){
        AnscTraceWarning(("Failed to get parameter value for '%s'\n", param));
        goto get_negative_result;
     }
    
     if(size >= 1){
        snprintf(val, len, "%s", parameterVal[0]->parameterValue);
        Cosa_FreeParamValues(size, parameterVal);
     }
     
     if( ppDestComponentName){   AnscFreeMemory(ppDestComponentName); ppDestComponentName = NULL;}
     if( ppDestPath){   AnscFreeMemory(ppDestPath); ppDestPath = NULL;}

     return 0;

get_negative_result:
     if( ppDestComponentName){   AnscFreeMemory(ppDestComponentName); ppDestComponentName = NULL;}
     if( ppDestPath){   AnscFreeMemory(ppDestPath); ppDestPath = NULL;}

     return -1;
}

/* 
 * set value to data model 
 * return 0 if OK and -1 on error 
 */
int set_dm_value(const char *param, char *val, size_t vlen)
{
    UNREFERENCED_PARAMETER(vlen);
    char                    *ppDestComponentName = NULL;
    char                    *ppDestPath = NULL;
    parameterValStruct_t    **structGet = NULL;
    parameterValStruct_t    structSet[1];
    int                     valNum;
    
    if (!param || !val){
        AnscTraceWarning(("%s: bad parameters\n", __FUNCTION__));
        return -1;
    }
    
    if (!Cosa_FindDestComp((char *)param, &ppDestComponentName, &ppDestPath)){
        AnscTraceWarning(("Failed to find the CCSP component who supports '%s'\n", param));

        goto set_negative_result;
    }
    
    /* get values for it's type */
    if (!Cosa_GetParamValues(ppDestComponentName,
             ppDestPath,
             (char **)&param,
             1,
             &valNum ,
             &structGet)){
        AnscTraceWarning(("Failed to get parameter value for '%s'\n", param));

        goto set_negative_result;
    }
    
    if (valNum != 1 || strcmp(structGet[0]->parameterName, param) != 0)
    {
        AnscTraceWarning(("%s: miss match\n", __FUNCTION__));
        Cosa_FreeParamValues(valNum, structGet);

        goto set_negative_result;
    }
    
    structSet[0].parameterName = (char *)param;
    structSet[0].parameterValue = val;
    structSet[0].type = (*structGet)[0].type;

    if(!Cosa_SetParamValuesNoCommit(
		    ppDestComponentName,
 			ppDestPath,
			structSet,
			1)){

        goto set_negative_result;
    }

#if 0
    /* No need to commit. Generic handler will commit */
    if (!Cosa_SetCommit(ppDestComponentName, ppDestPath, TRUE)){
        AnscTraceWarning(("%s commit failed\n", ppDestPath));
        goto set_negative_result;
    }
#endif

    Cosa_FreeParamValues(valNum, structGet);

    if( ppDestComponentName){   AnscFreeMemory(ppDestComponentName); ppDestComponentName = NULL;}
    if( ppDestPath){   AnscFreeMemory(ppDestPath); ppDestPath = NULL;}

    return 0;

set_negative_result:
    if( ppDestComponentName){   AnscFreeMemory(ppDestComponentName); ppDestComponentName = NULL;}
    if( ppDestPath){   AnscFreeMemory(ppDestPath); ppDestPath = NULL;}

    return -1;
}

