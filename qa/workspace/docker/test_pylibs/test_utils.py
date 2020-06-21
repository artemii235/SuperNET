from .mm2proxy import MMProxy
from .mm2node import MMnode
from slickrpc import Proxy as KMDProxy
from pycurl import error as perror
import pycurl
import time
import string
import random
import ujson
import logging


def rand_value(vmin: float, vmax: float) -> str:
    assert vmax > vmin
    return "{0:.8f}".format(vmin + (random.random() * (vmax - vmin)))


def rand_item(items: list) -> object:
    return random.choice(items)


def init_logs() -> logging:
    log = logging.getLogger(__name__)
    return log


def randomstring(length: int) -> str:
    chars = string.ascii_letters
    return ''.join(random.choice(chars) for i in range(length))


def check_proxy_connection(mmproxy: MMProxy) -> bool:
    """Test RPC server availability"""
    attempt = 0
    while attempt < 40:
        try:
            mmproxy.version()
        except pycurl.error as e:
            print(e)
            time.sleep(2)
            attempt += 1
            if attempt >= 40:
                return False
    return True


def start_mm2_node(log: logging, mode: str, host='127.0.0.1'):
    """Start mm2 node in selected mode and enable coins"""
    electrums_a = ["node.sirseven.me:15001", "node.sirseven.me:25001"]
    electrums_b = ["node.sirseven.me:35001", "node.sirseven.me:45001"]
    coin_a = 'WSG'
    coin_b = 'BSG'
    bindir = '/atomicDEX/mmbin'
    with open('saturation.json') as j:
        test_params = ujson.load(j)
    node = MMnode(test_params.get(mode).get('seed'), '7783',
                  test_params.get('seednodes'), bindir, test_params.get(mode).get('ntype'))
    log.info("starting mm2 node as: %s", mode)
    node.start()
    proxy = node.rpc_conn(host)
    assert check_proxy_connection(proxy)
    enable_electrums(proxy, electrums_a, electrums_b, coin_a, coin_b)
    log.info("mm2 node connected, coins enabled")


def enable_electrums(proxy: MMProxy, electrums_base: list, electrums_rel: list, base: str, rel: str) -> bool:
    """Enable coins on mm2 node with electrum API method"""
    servers_base = []
    servers_rel = []
    for electrum in electrums_base:
        servers_base.append({'url': electrum, 'protocol': 'TCP', "disable_cert_verification": True})
    for electrum in electrums_rel:
        servers_rel.append({'url': electrum, 'protocol': 'TCP', "disable_cert_verification": True})
    attempt = 0
    while attempt < 40:
        proxy.electrum(coin=base, servers=servers_base)
        res2 = proxy.electrum(coin=rel, servers=servers_rel)
        if not res2.get('error'):
            break
        else:
            attempt += 1
            time.sleep(10)
    if attempt >= 10:
        return False
    return True


def init_connection(mm2userpass: str, mm_nodes: list) -> dict:
    """Creates MM2 proxies"""
    mm_proxy = {}
    for node in mm_nodes:  # connect to all mm nodes
        node_params_dictionary = {
            'userpass': mm2userpass,  # userpass to be used in jsonrpc
            'rpchost': node,
            'rpcport': 7783
        }
        try:
            proxy = MMProxy(node_params_dictionary, timeout=120)
        except ConnectionAbortedError as e:
            raise Exception("Connection error! Probably no daemon on selected port. Error: ", e)
        mm_proxy.update({node: proxy})
        # check connections
        while True:
            attempt = 0
            try:
                res = proxy.version()
                print(res)
                break
            except perror as e:
                attempt += 1
                print('MM2 does not respond, retrying\nError: ', e)
                if attempt > 15:
                    raise Exception("Connection error ", e)
                else:
                    time.sleep(5)
    return mm_proxy


def get_orders_amount(proxy: MMProxy, base: str, rel: str) -> dict:
    """Get amount of orders from node"""
    res = proxy.orderbook(base=base, rel=rel)
    asks = res.get('numasks')
    bids = res.get('numbids')
    orders = {
        'numasks': asks,
        'numbids': bids,
        'amount': asks+bids
    }
    return orders


def check_saturation(vol1: int, vol2: int) -> bool:
    """Check if percentage of orders received is acceptable"""
    acceptance = 0.95
    volume = sorted([vol1, vol2])
    try:
        if volume[0]/volume[1] >= acceptance:
            return True
        else:
            return False
    except ZeroDivisionError:
        return False


def komodo_setgenerate(kmd_nodes: list, user: str, passwd: str) -> bool:
    """Waits for komodod nodes to accept connection and enables mining"""
    i = 0
    attempt = 0
    rpc = []
    for node in kmd_nodes:
        node = "http://" + user + ':' + passwd + '@' + node
        rpc.append(KMDProxy(node))
        while attempt < 40:  # Check node is active
            try:
                rpc[i].getinfo()
                break
            except perror as e:
                attempt += 1
                print("Retrying connection " + node + "\n error: " + str(e))
                time.sleep(1)
        if attempt >= 40:
            return False
        rpc[i].setgenerate(True, 1)
    return True


def check_for_errors(resp: dict, uuid: str) -> bool:  # resp - mm2proxy response dictionary
    """Prints error message and returns True if response is {"error": "error_message"}"""
    try:
        if resp.get('error') and resp.get('error') != 'swap data is not found':
            print("\n error finding uuid: " + uuid + " response " + str(resp) + "resp.get(error)" +
                  str(resp.get('error')) + "\n")
            return True
        else:
            return False
    except AttributeError:
        return False


def check_swap_status(swaps_dict: dict, node_proxy: MMProxy) -> dict:
    """Iterates events in mm2 response to determine finished(failed or successful) swaps"""
    error_events = [
        "StartFailed",
        "NegotiateFailed",
        "TakerFeeValidateFailed",
        "MakerPaymentTransactionFailed",
        "MakerPaymentDataSendFailed",
        "TakerPaymentValidateFailed",
        "TakerPaymentSpendFailed",
        "MakerPaymentRefunded",
        "MakerPaymentRefundFailed",
        "MakerPaymentValidateFailed",
        "TakerFeeSendFailed"
    ]
    i = 0
    print("--\nChecking swaps status\n--")
    for uuid in swaps_dict:
        event_occur = []
        resp = node_proxy.my_swap_status(params={'uuid': uuid})
        if check_for_errors(resp, uuid):  # keeps swap status "unknown"
            event_occur.append('Error_response')
            time.sleep(5)  # prevents my_swap_status method spam
            pass
        else:
            try:
                events_list = resp.get('result').get('events')
                for single_event in events_list:
                    event_type = single_event.get('event').get('type')
                    event_occur.append(event_type)
                    if event_type in error_events:
                        print("swap failed uuid: " + str(uuid))
                        swaps_dict.update({uuid: ("failed, event: " + event_type + " error: " +
                                                  single_event.get('event').get('data').get('error'))})
                        break
                    elif event_type == 'Finished':
                        print("swap success uuid: " + str(uuid))
                        swaps_dict.update({uuid: 'success'})
                    else:
                        pass
            except (AttributeError, KeyError):
                print("swap not found, uuid: " + str(uuid))
                swaps_dict.update({uuid: 'not_found'})
        print("Check step: " + str(i + 1) + "\nuuid: " + str(uuid) + " event types: " + str(event_occur))
        i += 1
    return swaps_dict


def swap_status_iterator(uuids_list: list, node_proxy: MMProxy) -> dict:
    """Builds swaps statuses dictionary"""
    swaps_d = dict.fromkeys(uuids_list, 'unknown')
    while True:
        work_d = {}  # intermediate dictionary to iterate unfinished swaps
        values_list = []
        for key in swaps_d:  # find unfinished swaps
            if swaps_d.get(key) == 'unknown':
                work_d.update({key: 'unknown'})
        res = check_swap_status(work_d, node_proxy)
        for key in res:  # update values
            swaps_d.update({key: res.get(key)})
            values_list.append(res.get(key))
        if 'unknown' not in values_list:  # stop iterator when all swaps are finished
            break
        time.sleep(20)  # check swap statuses trice per minute
    return swaps_d


def swaps_all(swaps: dict) -> int:
    i = 0
    for _ in swaps:
        i += 1
    return i


def swaps_success(swaps: dict) -> int:
    i = 0
    for key in swaps:
        if swaps[key] == 'success':
            i += 1
    return i
