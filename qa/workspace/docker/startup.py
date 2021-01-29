from test_pylibs.test_utils import init_logs, start_mm2_node
import os
import ujson


def main():
    log = init_logs()
    mode = os.environ.get('MODE')
    with open('saturation.json') as j:
        test_params = ujson.load(j)
        host = test_params.get(mode).get('defhost')
    start_mm2_node(log, mode, host)


if __name__ == '__main__':
    main()
