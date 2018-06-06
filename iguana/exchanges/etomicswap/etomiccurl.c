#include "etomiccurl.h"
#include <curl/curl.h>

static char *ethRpcUrl = ETOMIC_URL;
pthread_mutex_t sendTxMutex = PTHREAD_MUTEX_INITIALIZER;

struct string {
    char *ptr;
    size_t len;
};

void init_eth_string(struct string *s) {
    s->len = 0;
    s->ptr = malloc(s->len+1);
    if (s->ptr == NULL) {
        fprintf(stderr, "malloc() failed\n");
        exit(EXIT_FAILURE);
    }
    s->ptr[0] = '\0';
}

size_t writefunc(void *ptr, size_t size, size_t nmemb, struct string *s)
{
    size_t new_len = s->len + size*nmemb;
    s->ptr = realloc(s->ptr, new_len+1);
    if (s->ptr == NULL) {
        fprintf(stderr, "realloc() failed\n");
        exit(EXIT_FAILURE);
    }
    memcpy(s->ptr+s->len, ptr, size*nmemb);
    s->ptr[new_len] = '\0';
    s->len = new_len;

    return size*nmemb;
}

cJSON *parseEthRpcResponse(char *requestResult)
{
    printf("Trying to parse ETH RPC response: %s\n", requestResult);
    cJSON *json = cJSON_Parse(requestResult);
    if (json == NULL) {
        printf("ETH RPC response parse failed!\n");
        return NULL;
    }
    cJSON *tmp = cJSON_GetObjectItem(json, "result");
    cJSON *error = cJSON_GetObjectItem(json, "error");
    cJSON *result = NULL;
    if (!is_cJSON_Null(tmp)) {
        result = cJSON_Duplicate(tmp, 1);
    } else if (error != NULL && !is_cJSON_Null(error)) {
        char *errorString = cJSON_PrintUnformatted(error);
        printf("Got ETH rpc error: %s\n", errorString);
        free(errorString);
    }
    cJSON_Delete(json);
    return result;
}

char* sendRequest(char* request)
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    curl = curl_easy_init();
    if (curl) {
        struct string s;
        init_eth_string(&s);

        headers = curl_slist_append(headers, "Accept: application/json");
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "POST");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
        curl_easy_setopt(curl, CURLOPT_URL, ethRpcUrl);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, request);
        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
        return s.ptr;
    } else {
        return NULL;
    }
}

cJSON *sendRpcRequest(char *method, cJSON *params)
{
    char* string;
    cJSON *request = cJSON_CreateObject();
    cJSON_AddStringToObject(request, "jsonrpc", "2.0");
    cJSON_AddStringToObject(request, "method", method);
    cJSON_AddItemToObject(request, "params", cJSON_Duplicate(params, 1));
    cJSON_AddNumberToObject(request, "id", 1);
    string = cJSON_PrintUnformatted(request);
    char* requestResult = sendRequest(string);
    free(string);
    cJSON_Delete(request);
    cJSON *result = parseEthRpcResponse(requestResult);
    free(requestResult);
    return result;
}

char* sendRawTxWaitConfirm(char* rawTx)
{
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(rawTx));
    cJSON *resultJson = sendRpcRequest("eth_sendRawTransaction", params);
    cJSON_Delete(params);
    char *txId = NULL;
    if (resultJson != NULL && is_cJSON_String(resultJson) && resultJson->valuestring != NULL) {
        char* tmp = resultJson->valuestring;
        txId = (char *) malloc(strlen(tmp) + 1);
        strcpy(txId, tmp);
    }
    /*
    if (resultJson != NULL && is_cJSON_String(resultJson) && resultJson->valuestring != NULL) {
        char* tmp = resultJson->valuestring;
        if (waitForConfirmation(tmp) > 0) {
            txId = (char *) malloc(strlen(tmp) + 1);
            strcpy(txId, tmp);
        }
    }
    */
    cJSON_Delete(resultJson);
    pthread_mutex_unlock(&sendTxMutex);
    return txId;
}

char* sendRawTx(char* rawTx)
{
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(rawTx));
    cJSON *resultJson = sendRpcRequest("eth_sendRawTransaction", params);
    cJSON_Delete(params);
    char *txId = NULL;
    if (resultJson != NULL && is_cJSON_String(resultJson) && resultJson->valuestring != NULL) {
        char* tmp = resultJson->valuestring;
        txId = (char *) malloc(strlen(tmp) + 1);
        strcpy(txId, tmp);
    }
    cJSON_Delete(resultJson);
    pthread_mutex_unlock(&sendTxMutex);
    return txId;
}

int64_t getNonce(char* address)
{
    // we should lock this mutex and unlock it only when transaction was already sent.
    // make sure that sendRawTx is called after getting a nonce!
    if (pthread_mutex_lock(&sendTxMutex) != 0) {
        printf("Nonce mutex lock failed\n");
    };
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(address));
    // cJSON_AddItemToArray(params, cJSON_CreateString("pending"));
    int64_t nonce = -1;
    cJSON *nonceJson = sendRpcRequest("parity_nextNonce", params);
    cJSON_Delete(params);
    if (nonceJson != NULL && is_cJSON_String(nonceJson) && nonceJson != NULL) {
        nonce = (int64_t) strtol(nonceJson->valuestring, NULL, 0);
    }
    cJSON_Delete(nonceJson);
    printf("Got ETH nonce %d\n", (int)nonce);
    return nonce;
}

char* getEthBalanceRequest(char* address)
{
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(address));
    cJSON_AddItemToArray(params, cJSON_CreateString("latest"));
    cJSON *balanceJson = sendRpcRequest("eth_getBalance", params);
    cJSON_Delete(params);
    char *balance = NULL;
    if (balanceJson != NULL && is_cJSON_String(balanceJson) && balanceJson->valuestring != NULL) {
        balance = (char *) malloc(strlen(balanceJson->valuestring) + 1);
        strcpy(balance, balanceJson->valuestring);
    }
    cJSON_Delete(balanceJson);
    return balance;
}

char* ethCall(char* to, const char* data)
{
    cJSON *params = cJSON_CreateArray();
    cJSON *txObject = cJSON_CreateObject();
    cJSON_AddStringToObject(txObject, "to", to);
    cJSON_AddStringToObject(txObject, "data", data);
    cJSON_AddItemToArray(params, txObject);
    cJSON_AddItemToArray(params, cJSON_CreateString("latest"));
    cJSON *resultJson = sendRpcRequest("eth_call", params);
    cJSON_Delete(params);
    char* result = NULL;
    if (resultJson != NULL && is_cJSON_String(resultJson) && resultJson->valuestring != NULL) {
        result = (char *) malloc(strlen(resultJson->valuestring) + 1);
        strcpy(result, resultJson->valuestring);
    }
    cJSON_Delete(resultJson);
    return result;
}

EthTxReceipt getEthTxReceipt(char *txId)
{
    EthTxReceipt result;
    memset(&result, 0, sizeof(result));
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(txId));
    cJSON *receiptJson = sendRpcRequest("eth_getTransactionReceipt", params);
    cJSON_Delete(params);
    if (receiptJson == NULL || is_cJSON_Null(cJSON_GetObjectItem(receiptJson, "blockHash")) || is_cJSON_Null(cJSON_GetObjectItem(receiptJson, "blockNumber"))) {
        printf("ETH tx %s is not confirmed yet or does not exist at all\n", txId);
        strcpy(result.blockHash, "0x0000000000000000000000000000000000000000000000000000000000000000");
        result.blockNumber = 0;
    } else {
        uint64_t currentBlockNumber = getEthBlockNumber();
        strcpy(result.blockHash, cJSON_GetObjectItem(receiptJson, "blockHash")->valuestring);
        strcpy(result.status, cJSON_GetObjectItem(receiptJson, "status")->valuestring);
        result.blockNumber = (uint64_t) strtol(cJSON_GetObjectItem(receiptJson, "blockNumber")->valuestring, NULL, 0);
        if (currentBlockNumber >= result.blockNumber) {
            result.confirmations = currentBlockNumber - result.blockNumber + 1;
        }
    }
    cJSON_Delete(receiptJson);
    return result;
}

uint64_t getEthBlockNumber()
{
    uint64_t result = 0;
    cJSON *params = cJSON_CreateArray();
    cJSON *blockNumberJson = sendRpcRequest("eth_blockNumber", params);
    cJSON_Delete(params);
    if (blockNumberJson != NULL && is_cJSON_String(blockNumberJson) && blockNumberJson->valuestring != NULL) {
        result = (uint64_t) strtol(blockNumberJson->valuestring, NULL, 0);
    }
    cJSON_Delete(blockNumberJson);
    return result;
}

EthTxData getEthTxData(char *txId)
{
    EthTxData result;
    memset(&result, 0, sizeof(result));
    cJSON *params = cJSON_CreateArray();
    cJSON_AddItemToArray(params, cJSON_CreateString(txId));
    cJSON *dataJson = sendRpcRequest("eth_getTransactionByHash", params);
    cJSON_Delete(params);
    if (dataJson == NULL) {
        result.exists = 0;
        printf("ETH tx %s get data error or txId does not exist\n", txId);
    } else {
        result.exists = 1;
        strcpy(result.from, cJSON_GetObjectItem(dataJson, "from")->valuestring);
        strcpy(result.to, cJSON_GetObjectItem(dataJson, "to")->valuestring);
        strcpy(result.input, cJSON_GetObjectItem(dataJson, "input")->valuestring);
        strcpy(result.valueHex, cJSON_GetObjectItem(dataJson, "value")->valuestring);
    }
    free(dataJson);
    return result;
}

uint64_t getGasPriceFromStation()
{
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;
    curl = curl_easy_init();
    if (curl) {
        struct string s;
        init_eth_string(&s);

        headers = curl_slist_append(headers, "Accept: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
        curl_easy_setopt(curl, CURLOPT_URL, "https://ethgasstation.info/json/ethgasAPI.json");
        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK) {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            return DEFAULT_GAS_PRICE;
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
        cJSON *resultJson = cJSON_Parse(s.ptr);
        uint64_t result = DEFAULT_GAS_PRICE;
        free(s.ptr);
        if (resultJson == NULL) {
            return result;
        }

        if (is_cJSON_Number(cJSON_GetObjectItem(resultJson, "average"))) {
#ifdef ETOMIC_TESTNET
            result = (uint64_t)(cJSON_GetObjectItem(resultJson, "average")->valuedouble / 10) + 10;
#else
            result = (uint64_t)(cJSON_GetObjectItem(resultJson, "average")->valuedouble / 10) + 1;
#endif
        }
        cJSON_Delete(resultJson);
        return result;
    } else {
        return DEFAULT_GAS_PRICE;
    }
}

int32_t waitForConfirmation(char *txId)
{
    EthTxReceipt receipt;
    EthTxData txData;
    uint8_t retries = 0;
    do {
        receipt = getEthTxReceipt(txId);
        if (receipt.confirmations < 1) {
            txData = getEthTxData(txId);
            if (txData.exists == 0) {
                retries++;
                if (retries >= 30) {
                    printf("Have not found ETH tx %s after 10 checks, aborting\n", txId);
                    return (-1);
                }
            }
        } else {
            break;
        }
        printf("waiting for ETH txId to be confirmed: %s\n", txId);
        sleep(15);
    } while (1);

    if (strcmp(receipt.status, "0x1") != 0) {
        printf("ETH txid %s receipt status failed\n", txId);
        return(-1);
    }

    return((int32_t)receipt.confirmations);
}
