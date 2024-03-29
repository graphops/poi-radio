# Changelog

All notable changes to this project will be documented in this file.

## [unreleased]

### Bug Fixes

- Server context types
- Remove double Arc Mutex from state types
- Consistent nonce during build
- Msg comparison block available on remote
- Standarlize nonce across graphcast and radio
- Add test retries and gc msg valid check

### Documentation

- Update grafana config and default network subgraph endpoint

### Features

- Disable notifications for known divergences
- Add telegram notifications
- Discv5 configs
- Add e2e tests
- Serves represented indexer info query
- Add msg sender validation options
- Move e2e tests into separate files and add new scenarios
- Persist comparison results
- One-shot radio for version upgrade

### Miscellaneous Tasks

- Release 0.3.2
- Release 0.3.3
- Release 0.3.4
- Update sdk version
- Release 0.3.5
- Update tests
- Release 0.3.6
- Fix tests
- Grafana config and sdk-dep update
- Update sdk dep to 0.4.0
- Release 0.4.0

### Refactor

- Operator struct replaces global mutex
- Update interval constants
- Remove 'v' prefix from release tag
- New ratio formatting
- Update logging level
- Update to new sdk versions
- Switch to string ref
- Comparison results query resolver
- More msg fields and checks
- Radio message decode and handle multiple types
- Fix tests

## [0.3.1] - 2023-05-22

### Miscellaneous Tasks

- Release v0.3.1

### Refactor

- Update logging level

## [0.3.0] - 2023-05-20

### Features

- Ratio queries added, refactor logs
- Persist file for local attestations and remote msgs
- Add options to toggle logger format

### Miscellaneous Tasks

- Update dependencies without conflicts
- Update CI workflow and add docs
- Revert CI workflow
- Remove e2e test suite from repo
- Release 0.3.0

### Refactor

- Split comparison and gossip of POI

## [0.2.0] - 2023-05-09

### Bug Fixes

- Stake query address
- Stake query address #19
- Remove boot flag from Dockerfile
- Compare attestations check all local entries
- More checks for message uniqueness
- Check for null node
- Remove api metrics path
- Return empty vec if indexer_allocations function fails
- Radio name defined in main
- Disable unsubscribe and use timeout

### Documentation

- Updated pull request template (#77)
- Update release process and script

### Features

- Setup integration tests
- Build binaries and images
- Self-defined radio definition
- Self-defined radio definition #12
- Add workflow to build and upload Docker images
- Waku specific node key and log level
- Waku specific node key and log level #21
- Indexing network specific poi query
- Add multichain block clock
- Use environmental variable for pubsub
- Use environmental variable for pubsub #36
- Use indexing status to query block info
- Add update to allocation topics
- Use indexing status to query block info #35
- Tweak check for comparison trigger
- Env config block duration
- Env config block duration #41
- Sdk version update + use Config, add logs
- Add notifications
- Release note auto-gen and docker semvar tagging
- Pruning local+remote after expiry, update collect window to local
- Topic levels, stake by alloc status, logs calc
- Attestation indexer sender group sort and hash
- Add basic Prometheus support
- Add (auto)metrics & logs; fix: msg id & comparison and clean logic
- Basic http service for health/metrics/graphQL queries
- Add Grafana dashboard config
- Move integration tests to main repo
- New release process and changelog script
- GraphQL for comparison results and query arg options
- Add dumb-init to Docker image

### Miscellaneous Tasks

- Remove waku dep, use specific commit of sdk
- Bump graphcast-sdk version
- Bump version, publish to crates.io
- Add tag to Docker image
- Publish to crates.io
- Slim down Dockerfile
- Add ca-certificates to Dockerfile
- Bump version
- Bump SDK dep
- Rollback version number
- Tweak crates badge
- Release v0.1.1
- Release v0.1.3
- Release v0.2.0

### Refactor

- Improve Dockerfile
- Add tracing
- Fix release binaries workflow
- Default topics
- Update to new sdk error handling
- New graphcast registry link, rename graphcast vars
- New graphcast registry link, rename graphcast vars #31
- Remove provider for graph node query blocks
- Time based comparision
- Improve compare attestations logs
- Logging improvement
- Parallel messaging
- Update for attestation stake f32
- Add upx stage to Dockerfile
- Move config parsing to Radio
- Gossip poi refactoring and add benches

<!-- generated by git-cliff -->
