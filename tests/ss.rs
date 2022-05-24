use std::sync::Arc;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream},
    sync::oneshot::{self, Receiver, Sender},
};

use ss_rs::{
    context::Ctx,
    crypto::cipher::Method,
    tcp::{handle_ss_local, handle_ss_remote, SsTcpListener},
};

const REMOTE_ADDR: &str = "127.0.0.1:10800";
const LOCAL_ADDR: &str = "127.0.0.1:10801";

const METHOD: Method = Method::ChaCha20Poly1305;
const KEY: &str = "123456";

const REQ: &[u8] = b"\x05\x02\x00\x01\x05\x01\x00\x03\x09baidu.com\x00\x50GET / HTTP/1.0\r\n\r\n";

#[tokio::test]
async fn test() {
    let (tx1, rx1) = oneshot::channel::<()>();
    let (tx2, rx2) = oneshot::channel::<()>();

    let mut handles = Vec::new();

    handles.push(tokio::spawn(remote(tx1)));
    handles.push(tokio::spawn(local(tx2)));
    handles.push(tokio::spawn(client(rx1, rx2)));

    for handle in handles {
        handle.await.unwrap();
    }
}

async fn local(tx: Sender<()>) {
    let listener = TokioTcpListener::bind(LOCAL_ADDR).await.unwrap();
    tx.send(()).unwrap();

    let (stream, peer) = listener.accept().await.unwrap();
    handle_ss_local(
        stream,
        peer,
        REMOTE_ADDR.parse().unwrap(),
        METHOD,
        KEY.into(),
        Arc::new(Ctx::new()),
    )
    .await;
}

async fn remote(tx: Sender<()>) {
    let ctx = Arc::new(Ctx::new());
    let listener = SsTcpListener::bind(REMOTE_ADDR, METHOD, KEY.as_bytes(), ctx.clone())
        .await
        .unwrap();
    tx.send(()).unwrap();

    let (stream, peer) = listener.accept().await.unwrap();
    handle_ss_remote(stream, peer, ctx.clone()).await;
}

async fn client(rx1: Receiver<()>, rx2: Receiver<()>) {
    rx1.await.unwrap();
    rx2.await.unwrap();

    let mut client = TokioTcpStream::connect(LOCAL_ADDR).await.unwrap();
    client.write_all(REQ).await.unwrap();

    let mut buf = Vec::new();
    client.read_to_end(&mut buf).await.unwrap();

    let rsp = String::from_utf8(buf[12..].to_vec()).unwrap();
    assert!(!rsp.is_empty());
    println!("{}", rsp);
}
