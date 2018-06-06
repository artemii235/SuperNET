//
// Created by artem on 24.01.18.
//
#include <stdio.h>
#include <curl/curl.h>
#include <stdlib.h>
#include "etomiclib.h"
#include <cjson/cJSON.h>

char* aliceContractAddress = "0xe1D4236C5774D35Dc47dcc2E5E0CcFc463A3289c";
char* aliceAddress = "0x485d2cc2d13a9e12E4b53D606DB1c8adc884fB8a";
char* bobAddress = "0xA7EF3f65714AE266414C9E58bB4bAa4E6FB82B41";
char* tokenAddress = "0xc0eb7AeD740E1796992A08962c15661bDEB58003";

int main(int argc, char** argv) {
    enum { INIT_ETH, INIT_ERC20, ALICE_CLAIMS, BOB_CLAIMS, ALICE_APPROVES_ERC20 };

    if (argc < 2) {
        return 1;
    }

    int action = atoi(argv[1]);
    char* result;
    BasicTxData txData;
    switch (action)
    {
        case INIT_ETH:
            txData.amount = "1000000000000000000";
            txData.from = aliceAddress;
            txData.to = aliceContractAddress;
            txData.secretKey = getenv("ALICE_PK");

            AliceSendsEthPaymentInput input = {
                .dealId = argv[2],
                .bobAddress = bobAddress,
                .aliceHash = argv[3],
                .bobHash = argv[4]
            };

            result = aliceSendsEthPayment(input, txData);
            break;
        case INIT_ERC20:
            txData.amount = "0";
            txData.from = aliceAddress;
            txData.to = aliceContractAddress;
            txData.secretKey = getenv("ALICE_PK");

            AliceSendsErc20PaymentInput input1 = {
                .dealId = argv[2],
                .bobAddress = bobAddress,
                .aliceHash = argv[3],
                .bobHash = argv[4],
                .amount = "1000000000000000000",
                .tokenAddress = tokenAddress
            };

            result = aliceSendsErc20Payment(input1, txData);
            break;
        case ALICE_CLAIMS:
            txData.amount = "0";
            txData.from = aliceAddress;
            txData.to = aliceContractAddress;
            txData.secretKey = getenv("ALICE_PK");

            AliceReclaimsAlicePaymentInput input2 = {
                .dealId = argv[2],
                .bobAddress = bobAddress,
                .aliceHash = argv[3],
                .bobSecret = argv[4],
                .tokenAddress = argv[5],
                .amount = "1000000000000000000"
            };

            result = aliceReclaimsAlicePayment(input2, txData);
            break;
        case BOB_CLAIMS:
            txData.amount = "0";
            txData.from = bobAddress;
            txData.to = aliceContractAddress;
            txData.secretKey = getenv("BOB_PK");

            BobSpendsAlicePaymentInput input3 = {
                .dealId = argv[2],
                .aliceAddress = aliceAddress,
                .aliceSecret = argv[3],
                .bobHash = argv[4],
                .tokenAddress = argv[5],
                .amount = "1000000000000000000"
            };

            result = bobSpendsAlicePayment(input3, txData);
            break;
        case ALICE_APPROVES_ERC20:
            result = approveErc20(
                    "1000000000000000000",
                    "0x485d2cc2d13a9e12E4b53D606DB1c8adc884fB8a",
                    getenv("ALICE_PK")
            );
            break;
        default:
            return 1;
    }
    printf("%s\n", result);
    free(result);
    return 0;
}
