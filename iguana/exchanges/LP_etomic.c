
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
//  LP_etomic.c
//  marketmaker
//

//
// Created by artem on 24.01.18.
//
#include "LP_etomic.h"

int32_t LP_etomic_wait_for_confirmation(char *txId)
{
    return(waitForConfirmation(txId));
}

void LP_etomic_pubkeystr_to_addr(char *pubkey, char *output)
{
    char *address = pubKey2Addr(pubkey);
    strcpy(output, address);
    free(address);
}

char *LP_etomicalice_send_fee(struct basilisk_swap *swap)
{
    char amount[100], secretKey[70], dexaddr[50];
    satoshisToWei(amount, swap->myfee.I.amount);
    uint8arrayToHex(secretKey, swap->persistent_privkey.bytes, 32);
    LP_etomic_pubkeystr_to_addr(INSTANTDEX_PUBKEY, dexaddr);
    if (strcmp(swap->I.alicestr,"ETH") == 0 ) {
        return(sendEth(dexaddr, amount, secretKey, 1));
    } else {
        return(sendErc20(swap->I.alicetomic, dexaddr, amount, secretKey, 1));
    }
}

uint8_t LP_etomic_verify_alice_fee(struct basilisk_swap *swap)
{
    if (waitForConfirmation(swap->otherfee.I.ethTxid) < 0) {
        printf("Alice fee tx %s does not exist", swap->otherfee.I.ethTxid);
        return(0);
    }
    EthTxData data = getEthTxData(swap->otherfee.I.ethTxid);
    if (strcmp(data.from, swap->I.etomicdest) != 0) {
        printf("Alice fee tx %s was sent from wrong address %s\n", swap->otherfee.I.ethTxid, data.from);
        return(0);
    }

    char dexaddr[50];
    LP_etomic_pubkeystr_to_addr(INSTANTDEX_PUBKEY, dexaddr);
    if ( strcmp(swap->I.alicestr,"ETH") == 0 ) {
        if (strcmp(data.to, dexaddr) != 0) {
            printf("Alice fee %s was sent to wrong address %s\n", swap->otherfee.I.ethTxid, data.to);
            return(0);
        }
        uint64_t txValue = weiToSatoshi(data.valueHex);
        if (txValue != swap->otherfee.I.amount) {
            printf("Alice fee %s amount %" PRIu64 " is not equal to expected %" PRIu64 "\n", swap->otherfee.I.ethTxid, txValue, swap->otherfee.I.amount);
            return(0);
        }
        return(1);
    } else {
        if (strcmp(data.to, swap->I.alicetomic) != 0) {
            printf("Alice ERC20 fee %s token address %s is not equal to expected %s\n", swap->otherfee.I.ethTxid, data.to, swap->I.alicetomic);
            return(0);
        }
        char weiAmount[70];
        satoshisToWei(weiAmount, swap->otherfee.I.amount);
        return(verifyAliceErc20FeeData(swap->I.alicetomic, dexaddr, weiAmount, data.input));
    }
}

char *LP_etomicalice_send_payment(struct basilisk_swap *swap)
{
    AliceSendsEthPaymentInput input; AliceSendsErc20PaymentInput input20; BasicTxData txData;

    // set input and txData fields from the swap data structure
    memset(&txData,0,sizeof(txData));
    if ( strcmp(swap->I.alicestr,"ETH") == 0 )
    {
        memset(&input,0,sizeof(input));
        strcpy(input.bobAddress, swap->I.etomicsrc);
        uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input.dealId, swap->alicepayment.I.actualtxid.bytes, 32);

        strcpy(txData.from, swap->I.etomicdest);
        strcpy(txData.to, ETOMIC_ALICECONTRACT);
        satoshisToWei(txData.amount, swap->I.alicesatoshis);
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        return(aliceSendsEthPayment(input,txData));
    }
    else
    {
        memset(&input20,0,sizeof(input20));
        strcpy(input20.bobAddress, swap->I.etomicsrc);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input20.dealId, swap->alicepayment.I.actualtxid.bytes, 32);
        strcpy(input20.tokenAddress, swap->I.alicetomic);
        satoshisToWei(input20.amount, swap->I.alicesatoshis);

        strcpy(txData.from, swap->I.etomicdest);
        strcpy(txData.to, ETOMIC_ALICECONTRACT);
        strcpy(txData.amount, "0");
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        uint64_t allowance = getErc20Allowance(swap->I.etomicdest, ETOMIC_ALICECONTRACT, swap->I.alicetomic);
        if (allowance < swap->I.alicesatoshis) {
            printf("Alice token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.tokenAddress, swap->I.alicetomic);
            strcpy(approveErc20Input.owner, swap->I.etomicdest);
            strcpy(approveErc20Input.spender, ETOMIC_ALICECONTRACT);

            char *tokenBalance = getErc20BalanceHexWei(swap->I.etomicdest, swap->I.alicetomic);
            strcpy(approveErc20Input.amount, tokenBalance);
            free(tokenBalance);
            strcpy(approveErc20Input.secret, txData.secretKey);

            char *allowTxId = approveErc20(approveErc20Input);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return(aliceSendsErc20Payment(input20,txData));
    }
}

uint8_t LP_etomic_verify_alice_payment(struct basilisk_swap *swap, char *txId)
{
    if (waitForConfirmation(txId) < 0) {
        printf("Alice payment %s does not exist\n", txId);
        return(0);
    }
    EthTxData data = getEthTxData(txId);
    if (strcmp(data.to, ETOMIC_ALICECONTRACT) != 0) {
        printf("Alice payment %s was sent to wrong address %s\n", txId, data.to);
        return(0);
    }
    if (strcmp(data.from, swap->I.etomicdest) != 0) {
        printf("Alice payment %s was done from wrong address %s\n", txId, data.from);
        return(0);
    }
    AliceSendsEthPaymentInput input; AliceSendsErc20PaymentInput input20;

    if ( strcmp(swap->I.alicestr,"ETH") == 0 ) {
        uint64_t paymentAmount = weiToSatoshi(data.valueHex);
        if (paymentAmount != swap->I.alicesatoshis) {
            printf("Alice payment amount %" PRIu64 " does not match expected %" PRIu64 "\n", paymentAmount, swap->I.alicesatoshis);
            return(0);
        }
        memset(&input,0,sizeof(input));
        strcpy(input.bobAddress, swap->I.etomicsrc);
        uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input.dealId, swap->alicepayment.I.actualtxid.bytes, 32);

        return(verifyAliceEthPaymentData(input, data.input));
    } else {
        memset(&input20,0,sizeof(input20));
        strcpy(input20.bobAddress, swap->I.etomicsrc);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        uint8arrayToHex(input20.dealId, swap->alicepayment.I.actualtxid.bytes, 32);
        strcpy(input20.tokenAddress, swap->I.alicetomic);
        satoshisToWei(input20.amount, swap->I.alicesatoshis);

        return(verifyAliceErc20PaymentData(input20, data.input));
    }
}

char *LP_etomicalice_reclaims_payment(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->alicePaymentEthTx) < 0) {
        printf("Alice ETH payment %s is not found, can't reclaim\n", swap->alicePaymentEthTx);
        return NULL;
    }
    EthTxReceipt receipt = getEthTxReceipt(swap->alicePaymentEthTx);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Alice payment receipt status failed, can't reclaim\n");
        return NULL;
    }
    AliceReclaimsAlicePaymentInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.dealId, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    satoshisToWei(input.amount, swap->destamount);

    if (swap->alicetomic[0] != 0) {
        strcpy(input.tokenAddress, swap->alicetomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }
    strcpy(input.bobAddress, swap->etomicsrc);
    uint8arrayToHex(input.aliceHash, swap->secretAm, 20);
    bits256 invertedSecret;
    int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privBn.bytes[31 - i];
    }
    uint8arrayToHex(input.bobSecret, invertedSecret.bytes, 32);

    strcpy(txData.from, swap->etomicdest);
    strcpy(txData.to, ETOMIC_ALICECONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return aliceReclaimsAlicePayment(input, txData);
}

char *LP_etomicbob_spends_alice_payment(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->alicePaymentEthTx) < 0) {
        printf("Alice ETH payment %s is not found, can't spend\n", swap->alicePaymentEthTx);
        return NULL;
    }
    EthTxReceipt receipt = getEthTxReceipt(swap->alicePaymentEthTx);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Alice payment receipt status failed, can't spend\n");
        return NULL;
    }
    BobSpendsAlicePaymentInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.dealId, swap->txids[BASILISK_ALICEPAYMENT].bytes, 32);
    satoshisToWei(input.amount, swap->destamount);

    if (swap->alicetomic[0] != 0) {
        strcpy(input.tokenAddress, swap->alicetomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.aliceAddress, swap->etomicdest);
    bits256 invertedSecret; int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privAm.bytes[31 - i];
    }
    uint8arrayToHex(input.aliceSecret, invertedSecret.bytes, 32);
    uint8arrayToHex(input.bobHash, swap->secretBn, 20);

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_ALICECONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return bobSpendsAlicePayment(input, txData);
}

char *LP_etomicbob_sends_deposit(struct basilisk_swap *swap)
{
    BobSendsEthDepositInput input;
    BobSendsErc20DepositInput input20;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));
    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint8arrayToHex(input.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);
        input.lockTime = swap->bobdeposit.I.locktime;

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_BOBCONTRACT);
        satoshisToWei(txData.amount, swap->bobdeposit.I.amount);
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);
        return bobSendsEthDeposit(input, txData);
    } else {
        uint8arrayToHex(input20.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input20.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        satoshisToWei(input20.amount, swap->bobdeposit.I.amount);
        strcpy(input20.tokenAddress, swap->I.bobtomic);
        input20.lockTime = swap->bobdeposit.I.locktime;

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_BOBCONTRACT);
        strcpy(txData.amount, "0");
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        uint64_t allowance = getErc20Allowance(swap->I.etomicsrc, ETOMIC_BOBCONTRACT, swap->I.bobtomic);
        if (allowance < swap->bobdeposit.I.amount) {
            printf("Bob token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.tokenAddress, swap->I.bobtomic);
            strcpy(approveErc20Input.owner, swap->I.etomicsrc);
            strcpy(approveErc20Input.spender, ETOMIC_BOBCONTRACT);

            char *tokenBalance = getErc20BalanceHexWei(swap->I.etomicsrc, swap->I.bobtomic);
            strcpy(approveErc20Input.amount, tokenBalance);
            free(tokenBalance);
            strcpy(approveErc20Input.secret, txData.secretKey);

            char *allowTxId = approveErc20(approveErc20Input);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return bobSendsErc20Deposit(input20, txData);
    }
}

uint8_t LP_etomic_verify_bob_deposit(struct basilisk_swap *swap, char *txId)
{
    if (waitForConfirmation(txId) < 0) {
        printf("Bob deposit txid %s does not exist\n", txId);
        return(0);
    }
    EthTxData data = getEthTxData(txId);
    if (strcmp(data.to, ETOMIC_BOBCONTRACT) != 0) {
        printf("Bob deposit txid %s was sent to wrong address %s\n", txId, data.to);
        return(0);
    }
    if (strcmp(data.from, swap->I.etomicsrc) != 0) {
        printf("Bob deposit txid %s was sent from wrong address %s\n", txId, data.from);
        return(0);
    }
    BobSendsEthDepositInput input;
    BobSendsErc20DepositInput input20;
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));
    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint64_t depositAmount = weiToSatoshi(data.valueHex);
        if (depositAmount != swap->bobdeposit.I.amount) {
            printf("Bob deposit %s amount %" PRIu64 " != expected %" PRIu64 "\n", txId, depositAmount, swap->bobdeposit.I.amount);
            return(0);
        }
        uint8arrayToHex(input.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input.bobHash, swap->I.secretBn, 20);
        input.lockTime = swap->bobdeposit.I.locktime;

        return verifyBobEthDepositData(input, data.input);
    } else {
        uint8arrayToHex(input20.depositId, swap->bobdeposit.I.actualtxid.bytes, 32);
        strcpy(input20.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.bobHash, swap->I.secretBn, 20);
        satoshisToWei(input20.amount, swap->bobdeposit.I.amount);
        strcpy(input20.tokenAddress, swap->I.bobtomic);
        input20.lockTime = swap->bobdeposit.I.locktime;

        return verifyBobErc20DepositData(input20, data.input);
    }
}

char *LP_etomicbob_refunds_deposit(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->bobDepositEthTx) < 0) {
        printf("Bob deposit %s is not found, can't refund\n", swap->bobDepositEthTx);
        return NULL;
    }
    BobRefundsDepositInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    EthTxReceipt receipt = getEthTxReceipt(swap->bobDepositEthTx);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Bob deposit %s receipt status failed, can't refund\n", swap->bobDepositEthTx);
        return NULL;
    }
    uint8arrayToHex(input.depositId, swap->txids[BASILISK_BOBDEPOSIT].bytes, 32);
    strcpy(input.aliceAddress, swap->etomicdest);

    bits256 invertedSecret;
    int32_t i;
    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privBn.bytes[31 - i];
    }
    uint8arrayToHex(input.bobSecret, invertedSecret.bytes, 32);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }
    satoshisToWei(input.amount, swap->values[BASILISK_BOBDEPOSIT]);

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return bobRefundsDeposit(input, txData);
}

char *LP_etomicbob_sends_payment(struct basilisk_swap *swap)
{
    BobSendsEthPaymentInput input;
    BobSendsErc20PaymentInput input20;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));

    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint8arrayToHex(input.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
        input.lockTime = swap->bobpayment.I.locktime;

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_BOBCONTRACT);
        satoshisToWei(txData.amount, swap->bobpayment.I.amount);
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);
        return bobSendsEthPayment(input, txData);
    } else {
        uint8arrayToHex(input20.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input20.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        satoshisToWei(input20.amount, swap->bobpayment.I.amount);
        strcpy(input20.tokenAddress, swap->I.bobtomic);
        input20.lockTime = swap->bobpayment.I.locktime;

        strcpy(txData.from, swap->I.etomicsrc);
        strcpy(txData.to, ETOMIC_BOBCONTRACT);
        strcpy(txData.amount, "0");
        uint8arrayToHex(txData.secretKey, swap->persistent_privkey.bytes, 32);

        uint64_t allowance = getErc20Allowance(swap->I.etomicsrc, ETOMIC_BOBCONTRACT, swap->I.bobtomic);
        if (allowance < swap->bobpayment.I.amount) {
            printf("Bob token allowance is too low, setting new allowance\n");
            ApproveErc20Input approveErc20Input;
            strcpy(approveErc20Input.tokenAddress, swap->I.bobtomic);
            strcpy(approveErc20Input.owner, swap->I.etomicsrc);
            strcpy(approveErc20Input.spender, ETOMIC_BOBCONTRACT);

            char *tokenBalance = getErc20BalanceHexWei(swap->I.etomicsrc, swap->I.bobtomic);
            strcpy(approveErc20Input.amount, tokenBalance);
            free(tokenBalance);
            strcpy(approveErc20Input.secret, txData.secretKey);

            char *allowTxId = approveErc20(approveErc20Input);
            LP_etomic_wait_for_confirmation(allowTxId);
            free(allowTxId);
        }

        return bobSendsErc20Payment(input20, txData);
    }
}

uint8_t LP_etomic_verify_bob_payment(struct basilisk_swap *swap, char *txId)
{
    if (waitForConfirmation(txId) < 0) {
        printf("Bob payment %s is not found\n", txId);
        return 0;
    }
    EthTxData data = getEthTxData(txId);
    if (strcmp(data.to, ETOMIC_BOBCONTRACT) != 0) {
        printf("Bob payment %s was sent to wrong address %s\n", txId, data.to);
    }
    if (strcmp(data.from, swap->I.etomicsrc) != 0) {
        printf("Bob payment %s was sent from wrong address %s\n", txId, data.from);
    }
    BobSendsEthPaymentInput input;
    BobSendsErc20PaymentInput input20;
    memset(&input,0,sizeof(input));
    memset(&input20,0,sizeof(input20));

    if ( strcmp(swap->I.bobstr,"ETH") == 0 ) {
        uint64_t paymentAmount = weiToSatoshi(data.valueHex);
        if (paymentAmount != swap->bobpayment.I.amount) {
            printf("Bob payment %s amount %" PRIu64 " != expected %" PRIu64 "\n", txId, paymentAmount, swap->bobpayment.I.amount);
            return(0);
        }
        uint8arrayToHex(input.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input.aliceHash, swap->I.secretAm, 20);
        input.lockTime = swap->bobpayment.I.locktime;

        return verifyBobEthPaymentData(input, data.input);
    } else {
        uint8arrayToHex(input20.paymentId, swap->bobpayment.I.actualtxid.bytes, 32);
        strcpy(input20.aliceAddress, swap->I.etomicdest);
        uint8arrayToHex(input20.aliceHash, swap->I.secretAm, 20);
        satoshisToWei(input20.amount, swap->bobpayment.I.amount);
        strcpy(input20.tokenAddress, swap->I.bobtomic);
        input20.lockTime = swap->bobpayment.I.locktime;

        return verifyBobErc20PaymentData(input20, data.input);
    }
}

char *LP_etomicbob_reclaims_payment(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->bobPaymentEthTx) < 0) {
        printf("Bob payment %s is not found, can't reclaim\n", swap->bobPaymentEthTx);
        return NULL;
    }
    BobReclaimsBobPaymentInput input;
    BasicTxData txData;
    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));

    struct iguana_info *ecoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    EthTxReceipt receipt = getEthTxReceipt(swap->bobPaymentEthTx);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Bob payment receipt status failed, can't reclaim\n");
        return NULL;
    }
    uint8arrayToHex(input.paymentId, swap->txids[BASILISK_BOBPAYMENT].bytes, 32);
    strcpy(input.aliceAddress, swap->etomicdest);
    uint8arrayToHex(input.aliceHash, swap->secretAm, 20);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }
    satoshisToWei(input.amount, swap->values[BASILISK_BOBPAYMENT]);

    strcpy(txData.from, swap->etomicsrc);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return bobReclaimsBobPayment(input, txData);
}

char *LP_etomicalice_spends_bob_payment(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->bobPaymentEthTx) < 0) {
        printf("Bob payment %s is not found, can't spend\n", swap->bobPaymentEthTx);
        return NULL;
    }
    AliceSpendsBobPaymentInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    EthTxReceipt receipt = getEthTxReceipt(swap->bobPaymentEthTx);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Bob payment %s receipt status failed, can't spend\n", swap->bobPaymentEthTx);
        return NULL;
    }
    struct iguana_info *ecoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.paymentId, swap->txids[BASILISK_BOBPAYMENT].bytes, 32);
    satoshisToWei(input.amount, swap->values[BASILISK_BOBPAYMENT]);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.bobAddress, swap->etomicsrc);
    bits256 invertedSecret; int32_t i;

    for (i=0; i<32; i++) {
        invertedSecret.bytes[i] = swap->privAm.bytes[31 - i];
    }
    uint8arrayToHex(input.aliceSecret, invertedSecret.bytes, 32);

    strcpy(txData.from, swap->etomicdest);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return aliceSpendsBobPayment(input, txData);
}

char *LP_etomicalice_claims_bob_deposit(struct LP_swap_remember *swap)
{
    if (waitForConfirmation(swap->bobDepositEthTx) < 0) {
        printf("Bob deposit %s is not found, can't claim\n", swap->bobDepositEthTx);
        return NULL;
    }
    AliceClaimsBobDepositInput input;
    BasicTxData txData;

    memset(&txData,0,sizeof(txData));
    memset(&input,0,sizeof(input));
    EthTxReceipt receipt = getEthTxReceipt(swap->bobDepositEthTx);
    if (strcmp(receipt.status, "0x1") != 0) {
        printf("Bob deposit receipt status failed, can't claim\n");
        return NULL;
    }

    struct iguana_info *ecoin;
    bits256 privkey;
    ecoin = LP_coinfind("ETOMIC");
    privkey = LP_privkey(ecoin->symbol, ecoin->smartaddr, ecoin->taddr);

    uint8arrayToHex(input.depositId, swap->txids[BASILISK_BOBDEPOSIT].bytes, 32);
    satoshisToWei(input.amount, swap->values[BASILISK_BOBDEPOSIT]);

    if (swap->bobtomic[0] != 0) {
        strcpy(input.tokenAddress, swap->bobtomic);
    } else {
        strcpy(input.tokenAddress, "0x0000000000000000000000000000000000000000");
    }

    strcpy(input.bobAddress, swap->etomicsrc);
    uint8arrayToHex(input.bobHash, swap->secretBn, 20);

    strcpy(txData.from, swap->etomicdest);
    strcpy(txData.to, ETOMIC_BOBCONTRACT);
    strcpy(txData.amount, "0");
    uint8arrayToHex(txData.secretKey, privkey.bytes, 32);
    return aliceClaimsBobDeposit(input, txData);
}

char *sendEthTx(struct basilisk_swap *swap, struct basilisk_rawtx *rawtx)
{
    if (rawtx == &swap->alicepayment && swap->I.alicetomic[0] != 0) {
        return LP_etomicalice_send_payment(swap);
    } else if (rawtx == &swap->bobdeposit && swap->I.bobtomic[0] != 0) {
        return LP_etomicbob_sends_deposit(swap);
    } else if (rawtx == &swap->bobpayment && swap->I.bobtomic[0] != 0) {
        return LP_etomicbob_sends_payment(swap);
    } else if (swap->I.iambob == 0 && rawtx == &swap->myfee && swap->I.alicetomic[0] != 0) {
        return LP_etomicalice_send_fee(swap);
    } else {
        char *result = malloc(67);
        strcpy(result, EMPTY_ETH_TX_ID);
        return result;
    }
}

int32_t LP_etomic_priv2addr(char *coinaddr,bits256 privkey)
{
    char str[65],*addrstr;
    bits256_str(str,privkey);
    if ( (addrstr= privKey2Addr(str)) != 0 )
    {
        strcpy(coinaddr,addrstr);
        free(addrstr);
        return(0);
    }
    return(-1);
}

int32_t LP_etomic_priv2pub(uint8_t *pub64,bits256 privkey)
{
    char *pubstr,str[72]; int32_t retval = -1;
    bits256_str(str,privkey);
    if ( (pubstr= getPubKeyFromPriv(str)) != 0 )
    {
        if ( strlen(pubstr) == 130 && pubstr[0] == '0' && pubstr[1] == 'x' )
        {
            decode_hex(pub64,64,pubstr+2);
            retval = 0;
        }
        free(pubstr);
    }
    return(retval);
}

int32_t LP_etomic_pub2addr(char *coinaddr,uint8_t pub64[64])
{
    char pubkeystr[131],*addrstr;
    strcpy(pubkeystr,"0x");
    init_hexbytes_noT(pubkeystr+2,pub64,64);
    if ( (addrstr= pubKey2Addr(pubkeystr)) != 0 )
    {
        strcpy(coinaddr,addrstr);
        free(addrstr);
        return(0);
    }
    return(-1);
}

uint8_t LP_etomic_is_empty_tx_id(char *txId)
{
    if (strcmp(txId, EMPTY_ETH_TX_ID) == 0) {
        return 1;
    }
    return 0;
}

uint64_t LP_etomic_get_balance(struct iguana_info *coin, char *coinaddr)
{
    if (coin->etomic[0] == 0) {
        printf("Trying to get etomic balance for non-etomic coin %s!", coin->symbol);
        return 0;
    }

    if (strcmp(coin->symbol, "ETH") == 0) {
        return getEthBalance(coinaddr);
    } else {
        return getErc20BalanceSatoshi(coinaddr, coin->etomic);
    }
}
