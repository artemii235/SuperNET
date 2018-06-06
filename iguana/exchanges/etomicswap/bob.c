//
// Created by artem on 24.01.18.
//
#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include "etomiclib.h"
#include "etomiccurl.h"

char* bobContractAddress = "0x9387Fd3a016bB0205e4e131Dde886B9d2BC000A2";
char* aliceAddress = "0x485d2cc2d13a9e12E4b53D606DB1c8adc884fB8a";
char* bobAddress = "0xbAB36286672fbdc7B250804bf6D14Be0dF69fa29";
char* tokenAddress = "0xc0eb7AeD740E1796992A08962c15661bDEB58003";

void *erc20ApproveThread(ApproveErc20Input *input) {
    char *result = approveErc20(*input);
    free(result);
}

int main(int argc, char** argv)
{
    enum {
        BOB_ETH_DEPOSIT,
        BOB_ERC20_DEPOSIT,
        BOB_CLAIMS_DEPOSIT,
        ALICE_CLAIMS_DEPOSIT,
        BOB_ETH_PAYMENT,
        BOB_ERC20_PAYMENT,
        BOB_CLAIMS_PAYMENT,
        ALICE_CLAIMS_PAYMENT,
        BOB_APPROVES_ERC20,
        BOB_ETH_BALANCE,
        BOB_ERC20_BALANCE,
        TX_RECEIPT,
        TX_DATA
    };
    if (argc < 2) {
        return 1;
    }
    int action = atoi(argv[1]);
    BasicTxData txData;
    char* result;
    switch (action)
    {
        case BOB_ETH_DEPOSIT:
            strcpy(txData.amount, "1000000000000000000");
            strcpy(txData.from, bobAddress);
            strcpy(txData.to, bobContractAddress);
            strcpy(txData.secretKey, getenv("BOB_PK"));

            BobSendsEthDepositInput input;

            strcpy(input.aliceAddress, aliceAddress);
            strcpy(input.depositId, argv[2]);
            strcpy(input.bobHash, argv[3]);

            result = bobSendsEthDeposit(input, txData);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            break;
        case BOB_ERC20_DEPOSIT:
            strcpy(txData.amount, "0");
            strcpy(txData.from, bobAddress);
            strcpy(txData.to, bobContractAddress);
            strcpy(txData.secretKey, getenv("BOB_PK"));

            BobSendsErc20DepositInput input1 = {
                .amount = "1000000000000000000"
            };

            strcpy(input1.depositId, argv[2]);
            strcpy(input1.aliceAddress, aliceAddress);
            strcpy(input1.bobHash, argv[3]);
            strcpy(input1.tokenAddress, tokenAddress);

            result = bobSendsErc20Deposit(input1, txData);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            free(result);
            break;
        case BOB_CLAIMS_DEPOSIT:
            strcpy(txData.amount, "0");
            strcpy(txData.from, bobAddress);
            strcpy(txData.to, bobContractAddress);
            strcpy(txData.secretKey, getenv("BOB_PK"));

            BobRefundsDepositInput input2;
            strcpy(input2.depositId, argv[2]);
            strcpy(input2.amount, "1000000000000000000");
            strcpy(input2.aliceAddress, aliceAddress);
            strcpy(input2.tokenAddress, argv[3]);
            strcpy(input2.bobSecret, argv[5]);

            result = bobRefundsDeposit(input2, txData);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            free(result);
            break;
        case ALICE_CLAIMS_DEPOSIT:
            strcpy(txData.amount, "0");
            strcpy(txData.from, aliceAddress);
            strcpy(txData.to, bobContractAddress);
            strcpy(txData.secretKey, getenv("ALICE_PK"));

            AliceClaimsBobDepositInput input3;
            strcpy(input3.depositId, argv[2]);
            strcpy(input3.amount, "1000000000000000000");
            strcpy(input3.bobAddress, bobAddress);
            strcpy(input3.tokenAddress, argv[3]);
            strcpy(input3.bobHash, argv[5]);

            result = aliceClaimsBobDeposit(input3, txData);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            free(result);
            break;
        case BOB_ETH_PAYMENT:
            strcpy(txData.amount, "1000000000000000000");
            strcpy(txData.from, bobAddress);
            strcpy(txData.to, bobContractAddress);
            strcpy(txData.secretKey, getenv("BOB_PK"));

            BobSendsEthPaymentInput input4;
            strcpy(input4.paymentId, argv[2]);
            strcpy(input4.aliceHash, argv[3]);
            strcpy(input4.aliceAddress, aliceAddress);

            result = bobSendsEthPayment(input4, txData);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            free(result);
            break;
        case BOB_ERC20_PAYMENT:
            strcpy(txData.amount, "0");
            strcpy(txData.from, bobAddress);
            strcpy(txData.to, bobContractAddress);
            strcpy(txData.secretKey, getenv("BOB_PK"));

            BobSendsErc20PaymentInput input5;

            strcpy(input5.paymentId, argv[2]);
            strcpy(input5.amount, "1000000000000000000");
            strcpy(input5.tokenAddress, tokenAddress);
            strcpy(input5.aliceAddress, aliceAddress);
            strcpy(input5.aliceHash, argv[3]);

            result = bobSendsErc20Payment(input5, txData);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            free(result);
            break;
        case BOB_CLAIMS_PAYMENT:
            strcpy(txData.amount, "0");
            strcpy(txData.from, bobAddress);
            strcpy(txData.to, bobContractAddress);
            strcpy(txData.secretKey, getenv("BOB_PK"));

            BobReclaimsBobPaymentInput input6;

            strcpy(input6.paymentId, argv[2]);
            strcpy(input6.aliceAddress, aliceAddress);
            strcpy(input6.amount, "1000000000000000000");
            strcpy(input6.tokenAddress, argv[3]);
            strcpy(input6.aliceHash, argv[5]);

            result = bobReclaimsBobPayment(input6, txData);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            free(result);
            break;
        case ALICE_CLAIMS_PAYMENT:
            strcpy(txData.amount, "0");
            strcpy(txData.from, aliceAddress);
            strcpy(txData.to, bobContractAddress);
            strcpy(txData.secretKey, getenv("ALICE_PK"));

            AliceSpendsBobPaymentInput input7;

            strcpy(input7.paymentId, argv[2]);
            strcpy(input7.bobAddress, bobAddress);
            strcpy(input7.amount, "1000000000000000000");
            strcpy(input7.tokenAddress, argv[3]);
            strcpy(input7.aliceSecret, argv[5]);

            result = aliceSpendsBobPayment(input7, txData);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            break;
        case BOB_APPROVES_ERC20:
            printf("approving erc20\n");
            ApproveErc20Input input8;
            strcpy(input8.amount, "0");
            strcpy(input8.spender, bobContractAddress);
            strcpy(input8.owner, bobAddress);
            strcpy(input8.tokenAddress, tokenAddress);
            strcpy(input8.secret, getenv("BOB_PK"));
            ApproveErc20Input input123;
            strcpy(input123.amount, "100");
            strcpy(input123.spender, bobContractAddress);
            strcpy(input123.owner, bobAddress);
            strcpy(input123.tokenAddress, tokenAddress);
            strcpy(input123.secret, getenv("BOB_PK"));
            pthread_t t1, t2;
            pthread_create(&t1, NULL, erc20ApproveThread, &input8);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_create(&t2, NULL, erc20ApproveThread, &input123);
            pthread_join(t1, NULL);
            pthread_join(t2, NULL);
            /*result = approveErc20(input8);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
            result = approveErc20(&input8);
            if (result != NULL) {
                printf("%s\n", result);
                free(result);
            } else {
                printf("Tx send result was NULL\n");
            }
             */
            break;
        case BOB_ETH_BALANCE:
            printf("%" PRIu64 "\n", getEthBalance(bobAddress));
            break;
        case BOB_ERC20_BALANCE:
            printf("%" PRIu64 "\n", getErc20BalanceSatoshi(bobAddress, tokenAddress));
            break;
        case TX_RECEIPT:
            printf("getTxReceipt\n");
            EthTxReceipt txReceipt;
            txReceipt = getEthTxReceipt("0xc337b9cfe76aaa9022d9399a9e4ecdc1b7044d65ef74e8911a4b47874bee60c6");
            printf("blockNumber: %" PRIu64 "\n", txReceipt.blockNumber);
            printf("blockHash: %s\n", txReceipt.blockHash);
            printf("status: %s\n", txReceipt.status);
            printf("confirmations: %" PRIu64 "\n", txReceipt.confirmations);
            break;
        case TX_DATA:
            printf("getTxData\n");
            EthTxData ethTxData;
            ethTxData = getEthTxData("0xc337b9cfe76aaa9022d9399a9e4ecdc1b7044d65ef74e8911a4b47874bee60c6");
            printf("from : %s\n", ethTxData.from);
            printf("to: %s\n", ethTxData.to);
            printf("value: %s\n", ethTxData.valueHex);
            printf("input: %s\n", ethTxData.input);
            printf("exists: %d\n", ethTxData.exists);
            break;
        default:
            return 1;
    }
    char *pubkey = getPubKeyFromPriv(getenv("BOB_PK"));
    printf("pubkey: %s\n", pubkey);
    free(pubkey);

    char *address = pubKey2Addr("03bc2c7ba671bae4a6fc835244c9762b41647b9827d4780a89a949b984a8ddcc06");
    printf("address: %s\n", address);
    free(address);

    uint64_t satoshis = 100000000;
    char weiBuffer[100];
    satoshisToWei(weiBuffer, satoshis);
    printf("wei: %s\n", weiBuffer);

    uint8_t decimals = getErc20Decimals(tokenAddress);
    printf("decimals: %d\n", decimals);

    uint64_t tokenAllowance = getErc20Allowance(bobAddress, bobContractAddress, tokenAddress);
    printf("allowance: %" PRIu64 "\n", tokenAllowance);

    char *sendEthTx = sendEth(bobAddress, "100000000000000", getenv("BOB_PK"), 0);
    printf("sent ETH: %s\n", sendEthTx);
    free(sendEthTx);

    char *sendErc20Tx = sendErc20(tokenAddress, bobAddress, "100000000000000", getenv("BOB_PK"), 0);
    printf("sent Erc20: %s\n", sendErc20Tx);
    free(sendErc20Tx);

    uint64_t gasPrice = getGasPriceFromStation();
    printf("gasPrice: %" PRIu64 "\n", gasPrice);
    return 0;
}
