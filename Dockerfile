FROM rust as builder
WORKDIR /root/ss-rs
COPY . .
RUN cargo install --path .

FROM ubuntu
COPY --from=builder /usr/local/cargo/bin/ss-rs /usr/local/bin/
COPY --from=builder /root/ss-rs/acl /root/acl

EXPOSE 8000
