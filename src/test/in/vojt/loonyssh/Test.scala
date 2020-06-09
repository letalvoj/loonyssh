    // Should be turned into a test
    // val baos = new ByteArrayOutputStream(65536)
    // SSHWriter[Transport.BinaryPacket].write(SSHWriter.wrap(Kex), baos)
    // baos.flush
    // println(s"baos ${baos.toByteArray.toSeq}")

    // // Currently fails since the binary packet is not serialized properly
    // val pos = new PipedOutputStream()
    // val pis = new PipedInputStream(pos)
    // val bpis = new BufferedInputStream(pis)

    // SSHWriter[Transport.BinaryPacket].write(SSHWriter.wrap(Kex), pos)
    // val kexRecoveder = SSHReader[BinaryPacket[SSHMsg.KexInit]].read(pis)
    // println(Right(Kex) == kexRecoveder.map(_.payload)) // false
    // pos.close