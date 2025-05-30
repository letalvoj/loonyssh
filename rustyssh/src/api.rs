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

impl ReadSSH for [u8; 16] {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let mut buffer = [0u8; 16];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
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

impl ReadSSH for bool {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let mut buf = [0; 1];
        reader.read_exact(&mut buf)?;
        Ok(buf[0] != 0)
    }
}

impl ReadSSH for Vec<String> {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error> {
        let length = u32::read_ssh(&mut reader)? as usize;
        let mut name_list_bytes = vec![0; length];
        reader.read_exact(&mut name_list_bytes)?;

        let name_list = String::from_utf8(name_list_bytes)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid UTF-8"))?;

        if name_list.is_empty() && length == 0 { // Ensure it was an intentionally empty list
            Ok(Vec::new())
        } else {
            Ok(name_list.split(',').map(String::from).collect())
        }
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

//// Beware. Used to write enum discriminators. Do not overflow :)
impl WriteSSH for i32 {
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

impl ReadSSH for Vec<u8> {
    fn read_ssh<R: std::io::Read>(mut reader: R) -> Result<Self, std::io::Error>
    where
        Self: Sized,
    {
        let length = u32::read_ssh(&mut reader)? as usize;
        let mut buffer = vec![0; length];
        reader.read_exact(&mut buffer)?;
        Ok(buffer)
    }
}

impl WriteSSH for Vec<u8> {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let length = self.len() as u32;
        length.write_ssh(writer)?;
        writer.write_all(self)
    }
}

impl WriteSSH for &'static str {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self.as_bytes())?;
        Ok(())
    }
}

impl WriteSSH for u8 {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_u8(*self)
    }
}

impl WriteSSH for bool {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(&[*self as u8])
    }
}

impl WriteSSH for [u8; 16] {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        writer.write_all(self)
    }
}

impl WriteSSH for Vec<String> {
    fn write_ssh<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        let name_list = self.join(",");
        let length = name_list.len() as u32;

        length.write_ssh(writer)?;
        writer.write_all(name_list.as_bytes())
    }
}
