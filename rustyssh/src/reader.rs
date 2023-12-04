

impl ReadSSH for u32 {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let mut buffer = [0; 4];
        reader.read_exact(&mut buffer)?;
        Ok(u32::from_be_bytes(buffer))
    }
}

impl ReadSSH for String {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let length = u32::read_ssh(&mut reader)? as usize;
        let mut buffer = vec![0; length];
        reader.read_exact(&mut buffer)?;

        String::from_utf8(buffer).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8"))
    }
}