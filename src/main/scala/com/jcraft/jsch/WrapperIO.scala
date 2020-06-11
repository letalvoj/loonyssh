package com.jcraft.jsch

import java.io.InputStream
import java.io.OutputStream

class WrapperIO(in: InputStream, out: OutputStream, outExt: OutputStream) extends IO {
  super.setInputStream(in)
  super.setOutputStream(out)
  super.setExtOutputStream(outExt)
  new String()
}


