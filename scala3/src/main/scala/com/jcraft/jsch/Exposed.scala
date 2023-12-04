package com.jcraft.jsch

object Exposed {

    def guess(I_S: Array[Byte], I_C: Array[Byte]): Array[String] = KeyExchange.guess(I_S, I_C)

    def fromPoint(point: Array[Byte]): Array[Array[Byte]] = KeyPairECDSA.fromPoint(point)

}
