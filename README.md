# mock-relay
This is a simple service implementing the [builder API](https://github.com/ethereum/builder-specs). This is meant 
to be used as testing tool for consensus clients, especially in testnets where an actual relay might not be available 
(i.e, local testnets).

## Build
This will install, in `mock-relay` in `~/.cargo/bin`. [Rust](https://rustup.rs/) is required.
```
make
```
## Run
By default, `mock-relay` runs on `127.0.0.1:8650` and attempts to connect to an execution engine on `8551`. A JWT secret is 
usually required, the same one used by the execution engine you are attempting to connect to. 
```
./mock-relay --jwt-secret YOUR_JWT_SECRET_PATH
```

If you'd like to use a mock-relay with empty payloads (apart from required fields), and no connected local execution 
engine, use the `--empty-payloads` flag, and you won't need to configure JWT.

```
./mock-relay --empty-payloads
```

To make mock-relay do *even less* you can provide a default fee recipient in order to get valid payloads without registering
validators ahead of time. This is only possible in conjunction with the `--empty-payloads` flag.

```
./mock-relay --empty-payloads --default-fee-recipient YOUR_FEE_RECIPIENT
```