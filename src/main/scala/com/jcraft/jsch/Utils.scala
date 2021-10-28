package com.jcraft.jsch

class Utils {

    def guess(I_S: Array[Byte], I_C: Array[Byte]): Array[String] = KeyExchange.guess(I_S, I_C)

}
