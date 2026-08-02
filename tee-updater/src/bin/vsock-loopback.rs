use anyhow::{Context, Result};
use clap::Parser;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::thread;
use vsock::{VsockAddr, VsockStream};

#[derive(Parser)]
#[command(about = "Forward enclave-local TCP to a fixed parent-instance vsock proxy")]
struct Args {
    #[arg(long, default_value = "127.0.0.2")]
    listen_ip: Ipv4Addr,
    #[arg(long, default_value_t = 443)]
    listen_port: u16,
    #[arg(long, default_value_t = 3)]
    parent_cid: u32,
    #[arg(long, default_value_t = 8443)]
    parent_port: u32,
}

fn main() -> Result<()> {
    let args = Args::parse();
    let listener = TcpListener::bind(SocketAddrV4::new(args.listen_ip, args.listen_port))
        .context("failed to bind enclave loopback listener")?;
    for connection in listener.incoming() {
        let tcp = connection.context("failed to accept loopback connection")?;
        let cid = args.parent_cid;
        let port = args.parent_port;
        thread::spawn(move || {
            if let Err(error) = relay(tcp, cid, port) {
                eprintln!("loopback relay connection failed: {error:#}");
            }
        });
    }
    Ok(())
}

fn relay(mut tcp: TcpStream, cid: u32, port: u32) -> Result<()> {
    let address = VsockAddr::new(cid, port);
    let mut vsock =
        VsockStream::connect(&address).context("failed to connect parent vsock proxy")?;
    let mut tcp_read = tcp.try_clone().context("failed to clone TCP stream")?;
    let mut vsock_read = vsock.try_clone().context("failed to clone vsock stream")?;

    let toward_parent = thread::spawn(move || io::copy(&mut tcp_read, &mut vsock));
    io::copy(&mut vsock_read, &mut tcp).context("failed relaying Google TLS response")?;
    toward_parent
        .join()
        .map_err(|_| anyhow::anyhow!("request relay thread panicked"))?
        .context("failed relaying Google TLS request")?;
    Ok(())
}
