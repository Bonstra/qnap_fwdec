pub mod crypto;

extern crate getopts;

use crypto::CryptoContext;
use getopts::Options;
use std::io::prelude::*;
use std::io;

const DEFAULT_BLOBSIZE: usize = 0x100000;
const BUFFER_SIZE: usize = 1024 * 256;

#[derive(Debug)]
struct EncParams {
    infile: String,
    outfile: String,
    key: String,
    blobsize: Option<usize>,
    modelname: Option<String>,
    fwver: Option<String>,
    fwdate: Option<String>
}

#[derive(Debug)]
struct DecParams {
    infile: String,
    outfile: String,
    key: String,
    blobsize: Option<usize>,
}

#[derive(Debug)]
enum Mode {
    Encrypt(EncParams),
    Decrypt(DecParams),
    Help
}

#[derive(Debug)]
struct FooterInfo {
    offset: u64,
    blobsize: usize,
    modelname: String,
    fwver: String,
    fwdate: String,
}

fn parse_usize(s: &str) -> Result<usize, std::num::ParseIntError> {
    use std::str::FromStr;
    if s.starts_with("0x") {
        return usize::from_str_radix(&s[2..], 16);
    };
    usize::from_str(s)
}

fn print_usage(program: &str, opts: &Options) {
    use std::path::Path;
    let path = Path::new(program);
    let file = path.file_name().unwrap_or(path.as_os_str()).to_string_lossy();
    let brief = format!("Usage: {} [options] INFILE OUTFILE", file);
    print!("{}", opts.usage(&brief));
}

fn parse_args(args: &[String]) -> Option<Mode> {
    let mut opts = Options::new();
    opts.optflag("h", "help", "print this help message");
    opts.optflag("e", "encrpyt", "select encryption mode");
    opts.optflag("d", "decrpyt", "select decryption mode");
    opts.optopt("k", "key", "set encryption key", "KEY");
    opts.optopt("s", "size",
                &format!("size of data to encrypt; when decrypting, override
                          the size value read from the footer (default:
                          0x{:x})", DEFAULT_BLOBSIZE), "SIZE");
    opts.optopt("M", "model", "set model name (with -e only)", "MODEL");
    opts.optopt("V", "fwver", "set firmware version (with -e only)",
                "FWVER");
    opts.optopt("D", "fwdate", "set firmware date (with -e only)", "FWDATE");

    let matches;
    match opts.parse(&args[1..]) {
        Ok(m) => matches = m,
        Err(e) => {
            println!("{}", e);
            print_usage(&args[0], &opts);
            return None;
        }
    }

    if matches.opt_present("h") {
        print_usage(&args[0], &opts);
        return Some(Mode::Help);
    }

    if matches.free.len() != 2 {
        println!("Wrong number of arguments ({} instead of 2).",
                 matches.free.len());
        print_usage(&args[0], &opts);
        return None;
    }

    let key = match matches.opt_str("k") {
        Some(k) => k,
        None => {
            println!("No key (-k) given.");
            print_usage(&args[0], &opts);
            return None;
        }
    };

    let blobsize = match matches.opt_str("s") {
        Some(s) => match parse_usize(&s) {
            Ok(s) => Some(s),
            Err(e) => {
                println!("Invalid argument for -s: {}", e);
                print_usage(&args[0], &opts);
                return None;
            }
        },
        None => None
    };

    let enc = matches.opt_present("e");
    let dec = matches.opt_present("d");
    if !enc && !dec {
        println!("One of -e or -d must be specified.");
        print_usage(&args[0], &opts);
        return None;
    } else if enc && dec {
        println!("Flags -e and -d are mutually exclusive.");
        print_usage(&args[0], &opts);
        return None;
    } else if enc {
        let params = EncParams {
            infile: matches.free[0].clone(),
            outfile: matches.free[1].clone(),
            key: key,
            blobsize: blobsize,
            modelname: matches.opt_str("M"),
            fwver: matches.opt_str("V"),
            fwdate: matches.opt_str("D")
        };
        return Some(Mode::Encrypt(params));
    } else {
        let params = DecParams {
            infile: matches.free[0].clone(),
            outfile: matches.free[1].clone(),
            key: key,
            blobsize: blobsize
        };
        return Some(Mode::Decrypt(params));
    }
}

fn write_footer<T: Write>(out: &mut T, params: &EncParams) -> io::Result<()> {
    // Append footer
    let mut footer = [0u8; 0x4a];

    {
        let magic = &mut footer[0x0..0x6];
        magic.copy_from_slice("icpnas".as_bytes());
    }
    {
        let blobsize = &mut footer[0x6..0xa];
        let size = params.blobsize.unwrap_or(DEFAULT_BLOBSIZE);
        blobsize[0] = (size as u32 & 0xff) as u8;
        blobsize[1] = ((size as u32 >> 8) & 0xff) as u8;
        blobsize[2] = ((size as u32 >> 16) & 0xff) as u8;
        blobsize[3] = ((size as u32 >> 24) & 0xff) as u8;
    }
    if params.modelname.is_some() {
        let model = &mut footer[0xa..0x1a];
        let mdl = params.modelname.as_ref().unwrap().as_bytes();
        let fitting_len = if mdl.len() > model.len() {
            model.len()
        } else {
            mdl.len()
        };
        for i in 0..fitting_len {
            model[i] = mdl[i];
        };
    }
    if params.fwver.is_some() {
        let fwver = &mut footer[0x1a..0x2a];
        let ver = params.fwver.as_ref().unwrap().as_bytes();
        let fitting_len = if ver.len() > fwver.len() {
            fwver.len()
        } else {
            ver.len()
        };
        for i in 0..fitting_len {
            fwver[i] = ver[i];
        };
    }
    if params.fwdate.is_some() {
        let fwdate = &mut footer[0x2a..0x4a];
        let date = params.fwdate.as_ref().unwrap().as_bytes();
        let fitting_len = if date.len() > fwdate.len() {
            fwdate.len()
        } else {
            date.len()
        };
        for i in 0..fitting_len {
            fwdate[i] = date[i];
        };
    }

    try!(out.write_all(&footer));
    Ok(())
}

fn read_footer<T: Read + Seek>(reader: &mut T) -> io::Result<FooterInfo> {
    use std::io::SeekFrom;
    use std::io::{Error, ErrorKind};
    let ini_pos;
    let footer_offset;
    let mut buf = [0u8; 0x4a];

    ini_pos = try!(reader.seek(SeekFrom::Current(0)));
    footer_offset = try!(reader.seek(SeekFrom::End(-0x4a)));
    try!(reader.read_exact(&mut buf));
    {
        let magic = &buf[0x0..0x6];
        if magic != &b"icpnas"[..] {
            return Err(Error::new(ErrorKind::InvalidInput,
                                  "Incorrect magic value"));
        };
    }
    let blobsize = buf[0x6] as usize |
        ((buf[0x7] as usize) << 8) |
        ((buf[0x8] as usize) << 16) |
        ((buf[0x9] as usize) << 24);
    let modelname = String::from_utf8_lossy(&buf[0xa..0x1a]);
    let fwver = String::from_utf8_lossy(&buf[0x1a..0x2a]);
    let fwdate = String::from_utf8_lossy(&buf[0x2a..0x4a]);

    // Seek back to initial position
    try!(reader.seek(SeekFrom::Start(ini_pos)));

    Ok(FooterInfo {
        offset: footer_offset,
        blobsize: blobsize,
        modelname: modelname.into_owned(),
        fwver: fwver.into_owned(),
        fwdate: fwdate.into_owned(),
    })
}

fn encrypt(params: &EncParams) -> io::Result<()> {
    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufWriter;

    let reader = {
        let infile = try!(File::open(&params.infile));
        BufReader::with_capacity(BUFFER_SIZE, infile)
    };
    let mut writer = {
        let outfile = try!(File::create(&params.outfile));
        BufWriter::with_capacity(BUFFER_SIZE, outfile)
    };

    let blobsize = params.blobsize.unwrap_or(DEFAULT_BLOBSIZE);
    let mut ctx = CryptoContext::new(&params.key);
    let mut written = 0usize;

    for inbyte in reader.bytes() {
        if inbyte.is_err() {
            return Err(inbyte.err().unwrap());
        };
        let outbyte = if written < blobsize {
            ctx.encrypt(inbyte.unwrap())
        } else {
            inbyte.unwrap()
        };
        try!(writer.write_all(&[outbyte]));
        written += 1;
    }

    match write_footer(&mut writer, params) {
        Ok(_) => {},
        Err(err) => { return Err(err); }
    };

    Ok(())
}

fn decrypt(params: &DecParams) -> io::Result<()> {
    use std::fs::File;
    use std::io::BufReader;
    use std::io::BufWriter;

    let mut reader = {
        let infile = try!(File::open(&params.infile));
        BufReader::with_capacity(BUFFER_SIZE, infile)
    };
    let mut writer = {
        let outfile = try!(File::create(&params.outfile));
        BufWriter::with_capacity(BUFFER_SIZE, outfile)
    };

    let footer = try!(read_footer(&mut reader));
    println!("Model name: {}\n\
             FW version: {}\n\
             FW date: {}",
             footer.modelname,
             footer.fwver,
             footer.fwdate);

    let blobsize = params.blobsize.unwrap_or(footer.blobsize);
    let mut ctx = CryptoContext::new(&params.key);
    let mut written = 0usize;

    for inbyte in reader.bytes().take(footer.offset as usize) {
        if inbyte.is_err() {
            return Err(inbyte.err().unwrap());
        };
        let outbyte = if written < blobsize {
            ctx.decrypt(inbyte.unwrap())
        } else {
            inbyte.unwrap()
        };
        try!(writer.write_all(&[outbyte]));
        written += 1;
    }

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode: Mode;

    match parse_args(&args[..]) {
        Some(a) => mode = a,
        None => return
    }
    match mode {
        Mode::Encrypt(params) => {
            if let Err(err) = encrypt(&params) {
                println!("Encryption failed: {}", err);
                std::process::exit(1);
             };
        },
        Mode::Decrypt(params) => {
            if let Err(err) = decrypt(&params) {
                println!("Decryption failed: {}", err);
                std::process::exit(1);
             };
        }
        Mode::Help => {}
    };
}

