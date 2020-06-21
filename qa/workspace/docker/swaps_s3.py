from test_pylibs.test_utils import init_logs, enable_electrums, swap_status_iterator, init_connection, rand_value,\
                                   swaps_all, swaps_success, rand_item
import time
from decimal import Decimal
import pytest


def mainloop(maker: object, takers: list, coin_a: str, coin_b: str, log: object):
    time_sleep = 30
    swap_uuids = []
    swaps_to_run = 10
    step = 10
    check = True
    log.info("Entering main test loop")
    while check:  # run swaps until failure occur
        log.debug("Clearing up previous orders in %s s", str(time_sleep))
        maker.cancel_all_orders(cancel_by={'type': 'All'})  # reset orders
        for node in takers:
            node.cancel_all_orders(cancel_by={'type': 'All'})
        time.sleep(time_sleep)
        price1 = rand_value(0.81, 0.995)  # gen prices and volumes for swap
        volume1 = "{0:.8f}".format(Decimal(rand_value(0.1, 0.2)) * Decimal(swaps_to_run))
        log.info("Creating maker order in %s s", str(time_sleep))
        res = maker.setprice(base=coin_a, rel=coin_b, price=price1, volume=volume1, cancel_previous=False)
        log.debug("Response: %s", str(res))
        time.sleep(time_sleep)
        node = rand_item(takers)  # select on random client node to broadcast order
        for i in range(swaps_to_run):
            volume_to_swap = "{0:.8f}".format(((Decimal(volume1) * Decimal(rand_value(0.4, 0.5))) /
                                               Decimal(swaps_to_run)) + Decimal(0.00777))
            resp = node.buy(base=coin_a, rel=coin_b, price=price1, volume=volume_to_swap)
            assert not res.get('error')  # all orders should be successfully created
            log.debug("Create order, number: %s\n%s", str(i + 1), str(resp))
            if resp.get("result"):
                swap_uuids.append((resp.get("result")).get("uuid"))
            else:
                swap_uuids.append((resp.get("error")))
            time.sleep(3)
        log.debug("uuids: %s", str(swap_uuids))
        time.sleep(10)
        log.info("Waiting for swaps to finish")
        result = swap_status_iterator(swap_uuids, maker)
        log.info("Iteration result: %s", str(result))
        log.info("Out of %s swaps %s finished successfully", swaps_all(result), swaps_success(result))
        if swaps_all(result) == swaps_success(result):
            check = True
        else:
            check = False
        swap_uuids = []
        swaps_to_run += step
    log.info("\nTest result: %s", str(result))
    log.info("Out of %s swaps %s finished successfully", swaps_all(result), swaps_success(result))
    log.info("Setup: 3 clients, 4 seed nodes")


def test_swaps():
    log = init_logs()
    coin_a = 'WSG'
    coin_b = 'BSG'
    mm_nodes = ["mm_a", "mm_b", "mm_c", "mm_seed_a", "mm_seed_b", "mm_seed_c", "mm_seed_d"]
    log.info("Connecting to mm2 nodes")
    proxies = init_connection("RPC_PASSWORD", mm_nodes)
    electrums_base = ["node.sirseven.me:15001", "node.sirseven.me:25001"]
    electrums_rel = ["node.sirseven.me:15005", "node.sirseven.me:25005"]
    log.info("mm2 nodes connected, coins enabled")
    for node in mm_nodes:
        enable_electrums(proxies[node], electrums_base, electrums_rel, coin_a, coin_b)
    mainloop(proxies['mm_b'], [proxies['mm_a'], proxies['mm_c']], coin_a, coin_b, log)
