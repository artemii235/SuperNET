
/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/
//
//  LP_messages.c
//  marketmaker
//

struct LP_messageinfo { struct LP_messageinfo *next,*prev; cJSON *msgjson; int32_t ind; } *LP_MSGS;
int32_t Num_messages;

void LP_gotmessage(cJSON *argjson)
{
    struct LP_messageinfo *msg = calloc(1,sizeof(*msg));
    msg->msgjson = jduplicate(argjson);
    msg->ind = Num_messages++;
    portable_mutex_lock(&LP_messagemutex);
    DL_APPEND(LP_MSGS,msg);
    portable_mutex_unlock(&LP_messagemutex);
}

void LP_deletemessages(int32_t firsti,int32_t num)
{
    struct LP_messageinfo *msg,*tmp; int32_t lasti;
    if ( num == 0 )
        num = 100;
    if ( firsti < 0 )
        firsti = 0;
    else if ( firsti >= Num_messages )
        return;
    lasti = firsti + num - 1;
    if ( lasti < Num_messages-1 )
        lasti = Num_messages - 1;
    DL_FOREACH_SAFE(LP_MSGS,msg,tmp)
    {
        if ( msg->ind >= firsti && msg->ind <= lasti )
        {
            portable_mutex_lock(&LP_messagemutex);
            DL_DELETE(LP_MSGS,msg);
            portable_mutex_unlock(&LP_messagemutex);
            free_json(msg->msgjson);
            free(msg);
        }
    }
}

cJSON *LP_getmessages(int32_t firsti,int32_t num)
{
    struct LP_messageinfo *msg,*tmp; int32_t lasti,n=0,maxi=-1,mini=-1; cJSON *retjson,*item,*array = cJSON_CreateArray();
    retjson = cJSON_CreateObject();
    if ( num == 0 )
        num = 100;
    if ( firsti < 0 )
        firsti = 0;
    else if ( firsti >= Num_messages )
    {
        jadd(retjson,"messages",array);
        return(retjson);
    }
    lasti = firsti + num - 1;
    if ( lasti < Num_messages-1 )
        lasti = Num_messages - 1;
    DL_FOREACH_SAFE(LP_MSGS,msg,tmp)
    {
        if ( msg->ind >= firsti && msg->ind <= lasti )
        {
            item = cJSON_CreateObject();
            jaddnum(item,"ind",msg->ind);
            jadd(item,"msg",jduplicate(msg->msgjson));
            jaddi(array,item);
            if ( mini == -1 || msg->ind < mini )
                mini = msg->ind;
            if ( maxi == -1 || msg->ind > maxi )
                maxi = msg->ind;
            n++;
        }
    }
    jadd(retjson,"messages",array);
    jaddnum(retjson,"firsti",firsti);
    jaddnum(retjson,"lasti",lasti);
    jaddnum(retjson,"minind",mini);
    jaddnum(retjson,"maxind",maxi);
    jaddnum(retjson,"num",n);
    return(retjson);
}
