use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::packet::CapturedPacket;

pub struct Logger {
    writer: BufWriter<File>,
}

impl Logger {
    pub fn new(path: &str) -> std::io::Result<Self> {
        let file = File::create(Path::new(path))?;
        Ok(Self {
            writer: BufWriter::new(file),
        })
    }

    pub fn log_packet(&mut self, pkt: &CapturedPacket) -> Result<(), Box<dyn std::error::Error>> {
        serde_json::to_writer(&mut self.writer, pkt)?;
        self.writer.write_all(b"\n")?;
        self.writer.flush()?;
        Ok(())
    }
}
