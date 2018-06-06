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

#ifndef H_IGUANATYPES_H
#define H_IGUANATYPES_H


typedef void (*iguana_func)(void *);
typedef int32_t (*blockhashfunc)(uint8_t *blockhashp,uint8_t *serialized,int32_t len);
//typedef void *(*basilisk_func)(struct basilisk_item *Lptr,struct supernet_info *myinfo,struct iguana_info *coin,char *remoteaddr,uint32_t basilisktag,int32_t timeoutmillis,cJSON *vals);
//typedef double (*basilisk_metricfunc)(struct supernet_info *myinfo,struct basilisk_item *ptr,char *result);
//typedef struct _gfshare_ctx gfshare_ctx;

#endif

