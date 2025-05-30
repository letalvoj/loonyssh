package com.jcraft.jsch

import java.lang.reflect.Field

class WrapperSession(io: IO) extends Session(new JSch(), "", "", 22) {
    {
        val ioField: Field = this.getClass.getSuperclass.getDeclaredField("io")
        ioField.setAccessible(true)
        ioField.set(this, io).asInstanceOf[IO]
    }
}
