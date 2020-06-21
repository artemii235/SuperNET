## MM2 integration tests

Performed on release by GH Actions. [workflow](https://github.com/KomodoPlatform/atomicDEX-API/blob/mm2/.github/workflows/workflow.yml)

Underlying environment and network structure can be found [here](https://github.com/KomodoPlatform/mm2_testenv_composer).

Test scenarios are described below.

#### Saturation scenarios

Maker orders are propagated to the network until 5% or more are lost.

- S1
\
 Single client conencted to single seed node.
 
 - S2
 \
 Two client nodes, connected to single seed node. Orders are propagated by both client nodes, chosen randomly.

 - S3
 \
 Two client nodes, connected to two seed nodes.
 
 - S4
 \
 Similar to S3, seeds network extended to 4 nodes.

#### Swapping tests

Concurrent swaps are executed until 1st failure occur. Each test iteration adds 10 swaps, starting with the same number(10).

 - S1
 \
 The most simple setup. Single maker node, single taker node, single seed node.

 - S2
 \
 Single maker, single seed, two takers. Which taker will match maker order is chosen randomly for each single swap performed.

 - S3
 \
 Similar to S2, seed nodes network extended to 4 nodes.
 
#### Requirements:

```
Docker
docker-compose
```

#### Manual execution:

To start tests specify mm2 binary to be tested by providing repo(fork), commit sha and release tag in .env file.

AE:
```bash
../atomicDEX-API/qa$ cat .env
REPO=KomodoPlatform/atomicDEX-API
TAG=beta-2.0.2039
SHA=027db75a1
```

Copy desired scenario as docker-composer.yml, build and run workspace container:
 
 ```bash
../atomicDEX-API/qa$ cp saturation-s1-compose.yml docker-compose.yml
../atomicDEX-API/qa$ docker-compose build
../atomicDEX-API/qa$ docker-compose run workspace ; docker-compose down
 ```

Pytest and mm2 logs are saved to `atomicDEX-API/qa/logs/name.log`
