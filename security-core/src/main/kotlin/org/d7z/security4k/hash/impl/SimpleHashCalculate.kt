package org.d7z.security4k.hash.impl

import org.d7z.security4k.api.IStreamCalculate
import org.d7z.security4k.utils.foreach
import java.io.InputStream
import java.security.MessageDigest

class SimpleHashCalculate(private val name: String) : IStreamCalculate {
    init {
        MessageDigest.getInstance(name)
    }

    override fun calculateToBinary(input: InputStream): ByteArray {
        val md = MessageDigest.getInstance(name)
        input.foreach { bytes, len ->
            md.update(bytes, 0, len)
        }
        return md.digest()
    }
}
