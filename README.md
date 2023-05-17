# POI Radio

[![Docs](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://docs.graphops.xyz/graphcast/radios/poi-radio)
[![crates.io](https://img.shields.io/crates/v/poi-radio.svg)](https://crates.io/crates/poi-radio)

## Introduction

The key requirement for an Indexer to earn indexing rewards is to submit a valid Proof of Indexing (POI) promptly. The importance of valid POIs causes many Indexers to alert each other on subgraph health in community discussions. To alleviate the Indexer workload, this Radio utilized Graphcast SDK to exchange and aggregate POI along with a list of Indexer on-chain identities that can be used to trace reputations. With the pubsub pattern, the Indexer can get notified as soon as other indexers (with majority of stake) publish a POI different from the local POI.

[Documentation](https://docs.graphops.xyz/graphcast/radios/poi-radio) | [Packages](https://github.com/graphops/poi-radio/pkgs/container/poi-radio) | [Chat](https://discord.com/channels/438038660412342282/1087503343410225152) 

## 🧪 Testing

To run unit tests for the Radio. We recommend using [nextest](https://nexte.st/) as your test runner. Once you have it installed you can run the tests using the following commands:

```
cargo nextest run
```

There's also integration tests, which you can run with the included bash script:

```
sh run-tests.sh
```

## Contributing

We welcome and appreciate your contributions! Please see the [Contributor Guide](/CONTRIBUTING.md), [Code Of Conduct](/CODE_OF_CONDUCT.md) and [Security Notes](/SECURITY.md) for this repository.
