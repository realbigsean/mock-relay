# mock-relay
This is a simple service implementing the [mev-boost relay API](https://github.com/flashbots/mev-boost). This is meant 
to be used as testing tool for consensus clients, especially in testnets where an actual relay might not be available 
(i.e, local testnets). 

- `engine_forkchoiceUpdatedV1` - Calls here are forwarded to the local execution engine. 
- `relay_getPayloadHeaderV1` - Calls here are transformed into `engine_getPayloadV1` requests and sent to the local 
 execution engine. The response's full payload is cached and then converted into a payload header before being returned 
to the caller.  Currently, `SignedMEVPayloadHeader` will have an empty signature, but this will likely be updated in the future.
- `relay_proposeBlindedBlockV1` - The `transactions_root` of the blinded block is used to retrieve and return the cached 
full payload. This relay does not actually propose the block, this may also be added in the future.

## Build
This will install, in `mock-relay` in `~/.cargo/bin`. [Rust](https://rustup.rs/) is required.
```
make
```
## Run
By default, `mock-relay` runs on `127.0.0.1:8650` and attempts to connect to an execution engine on `8551`. A JWT secret is required, 
the same one used by the execution engine you are attempting to connect to. 
```
./mock-relay --jwt-secret YOUR_JWT_SECRET_PATH
```