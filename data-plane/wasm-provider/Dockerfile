FROM ghcr.io/corazawaf/coraza-proxy-wasm:0.6.0 AS wasm
FROM alpine:latest
COPY --from=wasm /plugin.wasm /coraza-proxy-wasm.wasm
CMD ["cp", "/coraza-proxy-wasm.wasm", "/shared/"]
