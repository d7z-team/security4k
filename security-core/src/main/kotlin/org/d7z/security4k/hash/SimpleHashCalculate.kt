package org.d7z.security4k.hash

import org.d7z.security4k.utils.foreach
import java.io.InputStream
import java.math.BigInteger
import java.security.MessageDigest

class SimpleHashCalculate(override val name: String) : BaseHashCalculate {
    init {
        MessageDigest.getInstance(name)
    }

    override fun calculate(input: InputStream): String {
        val md = MessageDigest.getInstance(name)
        input.foreach { bytes, len ->
            md.update(bytes, 0, len)
        }
        val bytes = md.digest()
        return BigInteger(1, bytes).toString(16).uppercase()
    }
}
