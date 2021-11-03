package com.jcraft.jsch

class ExposedBuffer extends Buffer {
    def getBuffer: Array[Byte] = this.buffer
    def getIndex: Int = index

    override def skip(n: Int): Unit = super.skip(n)
}
