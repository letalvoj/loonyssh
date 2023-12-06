use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};

pub trait ReadSSH {
    fn read_ssh<R: std::io::Read>(reader: R) -> Result<Self, std::io::Error>
    where
        Self: Sized;
}

impl ReadSSH for u8 {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        reader.read_u8()
    }
}

impl ReadSSH for [u8; 4] {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let mut buffer = [0u8; 4];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

impl ReadSSH for u32 {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        reader.read_u32::<BigEndian>()
    }
}

impl ReadSSH for [u32; 4] {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let mut array = [0u32; 4];
        for element in &mut array {
            *element = reader.read_u32::<BigEndian>()?;
        }
        Ok(array)
    }
}

impl ReadSSH for String {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let length = u32::read_ssh(&mut reader)? as usize;
        let mut buffer = vec![0; length];
        reader.read_exact(&mut buffer)?;

        String::from_utf8(buffer)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8"))
    }
}

pub trait WriteSSH {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()>;
}

impl WriteSSH for u32 {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&self.to_be_bytes())
    }
}

impl WriteSSH for String {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let length = self.len() as u32;
        length.write_ssh(writer)?;
        writer.write_all(self.as_bytes())
    }
}

impl WriteSSH for u8 {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u8(*self)
    }
}
