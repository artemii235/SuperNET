//
// Created by artem on 13.03.18.
//

#ifndef SUPERNET_LP_ETOMIC_H
#define SUPERNET_LP_ETOMIC_H
#include "etomicswap/etomiclib.h"
#include "etomicswap/etomiccurl.h"
#include <inttypes.h>
#include "LP_include.h"

int32_t LP_etomic_wait_for_confirmation(char *txId);

char *LP_etomicalice_send_fee(struct basilisk_swap *swap);

uint8_t LP_etomic_verify_alice_fee(struct basilisk_swap *swap);

char *LP_etomicalice_send_payment(struct basilisk_swap *swap);

uint8_t LP_etomic_verify_alice_payment(struct basilisk_swap *swap, char *txId);

char *LP_etomicalice_reclaims_payment(struct LP_swap_remember *swap);

char *LP_etomicbob_spends_alice_payment(struct LP_swap_remember *swap);

char *LP_etomicbob_sends_deposit(struct basilisk_swap *swap);

uint8_t LP_etomic_verify_bob_deposit(struct basilisk_swap *swap, char *txId);

char *LP_etomicbob_refunds_deposit(struct LP_swap_remember *swap);

char *LP_etomicbob_sends_payment(struct basilisk_swap *swap);

uint8_t LP_etomic_verify_bob_payment(struct basilisk_swap *swap, char *txId);

char *LP_etomicbob_reclaims_payment(struct LP_swap_remember *swap);

char *LP_etomicalice_spends_bob_payment(struct LP_swap_remember *swap);

char *LP_etomicalice_claims_bob_deposit(struct LP_swap_remember *swap);

char *sendEthTx(struct basilisk_swap *swap, struct basilisk_rawtx *rawtx);

int32_t LP_etomic_priv2addr(char *coinaddr,bits256 privkey);

int32_t LP_etomic_priv2pub(uint8_t *pub64,bits256 privkey);

int32_t LP_etomic_pub2addr(char *coinaddr,uint8_t pub64[64]);

uint8_t LP_etomic_is_empty_tx_id(char *txId);

uint64_t LP_etomic_get_balance(struct iguana_info *coin, char *coinaddr);

void LP_etomic_pubkeystr_to_addr(char *pubkey, char *output);

#endif //SUPERNET_LP_ETOMIC_H
