use std::fs::File;
use std::io::{Read, Write, Cursor, Seek, SeekFrom};
use std::net::UdpSocket;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use clap::{Parser, Subcommand};
use sha2::{Digest, Sha256};

const VERSION: u8 = 0x01;
const TYPE_HANDSHAKE: u8 = 0x00;
const TYPE_MANIFEST: u8 = 0x01;
const TYPE_DATA: u8 = 0x02;
const TYPE_ACK: u8 = 0x03;
const TYPE_CLOSE: u8 = 0x05;

const BLOCK_SIZE: usize = 1024;

#[derive(Parser)]
#[command(author, version, about = "PFTP demo")] 
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run in server mode
    Server {
        /// Address to listen on
        #[arg(short, long, default_value = "0.0.0.0:4444")]
        listen: String,
        /// Path to store received file
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Run in client mode
    Client {
        /// Server address
        #[arg(short, long)]
        server: String,
        /// File to send
        #[arg(short, long)]
        file: PathBuf,
    },
}

struct Header {
    version: u8,
    typ: u8,
    session_id: u32,
    seq: u32,
    timestamp: u32,
    checksum: u16,
}

impl Header {
    fn write_to(&self, w: &mut Vec<u8>) -> std::io::Result<()> {
        w.write_all(&[self.version, self.typ])?;
        w.write_u32::<BigEndian>(self.session_id)?;
        w.write_u32::<BigEndian>(self.seq)?;
        w.write_u32::<BigEndian>(self.timestamp)?;
        w.write_u16::<BigEndian>(self.checksum)?;
        Ok(())
    }

    fn read_from(r: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
        let version = r.read_u8()?;
        let typ = r.read_u8()?;
        let session_id = r.read_u32::<BigEndian>()?;
        let seq = r.read_u32::<BigEndian>()?;
        let timestamp = r.read_u32::<BigEndian>()?;
        let checksum = r.read_u16::<BigEndian>()?;
        Ok(Header { version, typ, session_id, seq, timestamp, checksum })
    }
}

fn now_ms() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64 as u32
}

fn main() -> std::io::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Server { listen, output } => run_server(&listen, &output),
        Commands::Client { server, file } => run_client(&server, &file),
    }
}

fn run_server(addr: &str, output: &PathBuf) -> std::io::Result<()> {
    let socket = UdpSocket::bind(addr)?;
    let mut buf = [0u8; 1500];
    println!("Listening on {}", addr);

    // Handshake
    let (len, peer) = socket.recv_from(&mut buf)?;
    let mut c = Cursor::new(&buf[..len]);
    let hdr = Header::read_from(&mut c)?;
    if hdr.typ != TYPE_HANDSHAKE {
        eprintln!("expected handshake");
        return Ok(());
    }
    let _flags = c.read_u8()?;
    let pk_len = c.read_u8()? as usize;
    let mut tmp = vec![0u8; pk_len];
    c.read_exact(&mut tmp)?; // ignore
    let _mtu = c.read_u16::<BigEndian>()?;

    // send handshake response
    let mut resp = Vec::new();
    Header {
        version: VERSION,
        typ: TYPE_HANDSHAKE,
        session_id: hdr.session_id,
        seq: 0,
        timestamp: now_ms(),
        checksum: 0,
    }.write_to(&mut resp)?;
    resp.extend_from_slice(&[0, 0]); // flags + pk len
    resp.write_u16::<BigEndian>(1500)?;
    socket.send_to(&resp, peer)?;

    // Manifest
    let (len, _) = socket.recv_from(&mut buf)?;
    let mut c = Cursor::new(&buf[..len]);
    let mh = Header::read_from(&mut c)?;
    if mh.typ != TYPE_MANIFEST {
        eprintln!("expected manifest");
        return Ok(());
    }
    let file_size = c.read_u64::<BigEndian>()?;
    let block_size = c.read_u32::<BigEndian>()? as usize;
    let block_count = c.read_u32::<BigEndian>()?;
    let _hash_alg = c.read_u8()?;
    let mut hashes = vec![0u8; block_count as usize * 32];
    c.read_exact(&mut hashes)?;

    // ack manifest
    let mut ack = Vec::new();
    Header {
        version: VERSION,
        typ: TYPE_ACK,
        session_id: mh.session_id,
        seq: 0,
        timestamp: now_ms(),
        checksum: 0,
    }.write_to(&mut ack)?;
    ack.write_u16::<BigEndian>(32)?; // window
    ack.write_u16::<BigEndian>(0)?; // bitmap len
    ack.write_u32::<BigEndian>(0)?; // cum ack
    socket.send_to(&ack, peer)?;

    let mut file = File::create(output)?;
    file.set_len(file_size)?;

    let mut received = 0u64;
    loop {
        let (len, _) = socket.recv_from(&mut buf)?;
        let mut c = Cursor::new(&buf[..len]);
        let h = Header::read_from(&mut c)?;
        match h.typ {
            TYPE_DATA => {
                let block_id = c.read_u32::<BigEndian>()?;
                let offset = c.read_u32::<BigEndian>()?;
                let data_len = c.read_u16::<BigEndian>()? as usize;
                let mut data = vec![0u8; data_len];
                c.read_exact(&mut data)?;
                let pos = block_id as u64 * block_size as u64 + offset as u64;
                file.seek(SeekFrom::Start(pos))?;
                file.write_all(&data)?;
                received += data_len as u64;
            }
            TYPE_CLOSE => {
                break;
            }
            _ => {}
        }
    }
    println!("Received {} bytes", received);

    // close ack
    let mut resp = Vec::new();
    Header {
        version: VERSION,
        typ: TYPE_CLOSE,
        session_id: mh.session_id,
        seq: 0,
        timestamp: now_ms(),
        checksum: 0,
    }.write_to(&mut resp)?;
    resp.write_u32::<BigEndian>(0)?;
    resp.write_u8(0)?;
    socket.send_to(&resp, peer)?;
    Ok(())
}

fn run_client(addr: &str, path: &PathBuf) -> std::io::Result<()> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect(addr)?;
    let session_id: u32 = rand::random();

    // handshake
    let mut buf = Vec::new();
    Header {
        version: VERSION,
        typ: TYPE_HANDSHAKE,
        session_id,
        seq: 0,
        timestamp: now_ms(),
        checksum: 0,
    }.write_to(&mut buf)?;
    buf.extend_from_slice(&[0, 0]);
    buf.write_u16::<BigEndian>(1500)?;
    socket.send(&buf)?;
    let mut resp = [0u8; 1500];
    socket.recv(&mut resp)?;

    // manifest
    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    let block_count = ((size + BLOCK_SIZE as u64 - 1) / BLOCK_SIZE as u64) as u32;
    let mut hashes = Vec::new();
    let mut buf_block = vec![0u8; BLOCK_SIZE];
    for _ in 0..block_count {
        let n = file.read(&mut buf_block)?;
        let mut hasher = Sha256::new();
        hasher.update(&buf_block[..n]);
        hashes.extend_from_slice(&hasher.finalize());
    }
    file.seek(SeekFrom::Start(0))?;

    let mut man = Vec::new();
    Header {
        version: VERSION,
        typ: TYPE_MANIFEST,
        session_id,
        seq: 1,
        timestamp: now_ms(),
        checksum: 0,
    }.write_to(&mut man)?;
    man.write_u64::<BigEndian>(size)?;
    man.write_u32::<BigEndian>(BLOCK_SIZE as u32)?;
    man.write_u32::<BigEndian>(block_count)?;
    man.write_u8(0x01)?;
    man.extend_from_slice(&hashes);
    socket.send(&man)?;
    socket.recv(&mut resp)?; // ack

    // send blocks
    for block_id in 0..block_count {
        let mut buf_pkt = Vec::new();
        Header {
            version: VERSION,
            typ: TYPE_DATA,
            session_id,
            seq: 2 + block_id,
            timestamp: now_ms(),
            checksum: 0,
        }.write_to(&mut buf_pkt)?;
        let n = file.read(&mut buf_block)?;
        buf_pkt.write_u32::<BigEndian>(block_id)?;
        buf_pkt.write_u32::<BigEndian>(0)?;
        buf_pkt.write_u16::<BigEndian>(n as u16)?;
        buf_pkt.extend_from_slice(&buf_block[..n]);
        socket.send(&buf_pkt)?;
    }

    // close
    let mut close = Vec::new();
    Header {
        version: VERSION,
        typ: TYPE_CLOSE,
        session_id,
        seq: 2 + block_count,
        timestamp: now_ms(),
        checksum: 0,
    }.write_to(&mut close)?;
    close.write_u32::<BigEndian>(block_count)?;
    close.write_u8(0)?;
    socket.send(&close)?;
    socket.recv(&mut resp)?; // close ack
    println!("Transfer complete");
    Ok(())
}

