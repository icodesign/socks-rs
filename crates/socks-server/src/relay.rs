use futures::future;
use tokio::io::{self, AsyncRead, AsyncWrite, AsyncWriteExt};

pub async fn relay<'a, L, R>(l: &'a mut L, r: &'a mut R) -> io::Result<(u64, u64)>
where
    L: AsyncRead + AsyncWrite + Unpin + ?Sized,
    R: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let (mut lr, mut lw) = io::split(l);
    let (mut rr, mut rw) = io::split(r);
    return relay_split(&mut lr, &mut lw, &mut rr, &mut rw).await;
}

pub async fn relay_split<'a, LR, LW, RR, RW>(
    mut lr: &'a mut LR,
    mut lw: &'a mut LW,
    mut rr: &'a mut RR,
    mut rw: &'a mut RW,
) -> io::Result<(u64, u64)>
where
    LR: AsyncRead + Unpin + ?Sized,
    LW: AsyncWrite + Unpin + ?Sized,
    RR: AsyncRead + Unpin + ?Sized,
    RW: AsyncWrite + Unpin + ?Sized,
{
    let client_to_server = transfer(&mut lr, &mut rw);
    let server_to_client = transfer(&mut rr, &mut lw);
    return future::try_join(client_to_server, server_to_client).await;
}

pub async fn transfer<'a, R, W>(reader: &'a mut R, writer: &'a mut W) -> io::Result<u64>
where
    R: AsyncRead + Unpin + ?Sized,
    W: AsyncWrite + Unpin + ?Sized,
{
    let len = io::copy(reader, writer).await?;
    writer.shutdown().await?;
    Ok(len)
}
