package org.d7z.security4k.hash.impl

import org.d7z.security4k.api.IStreamCalculate
import org.d7z.security4k.utils.foreach
import java.io.InputStream
import java.nio.ByteBuffer
import java.util.Locale
import java.util.zip.CRC32C

class CRC32CHashCalculate(val name: String = "CRC32C") : IStreamCalculate {
    override fun calculateToBinary(input: InputStream): ByteArray {
        val crc = CRC32C()
        input.foreach { bytes, i ->
            crc.update(bytes, 0, i)
        }
        val allocate = ByteBuffer.allocate(Long.SIZE_BYTES)
        allocate.putLong(crc.value)
        return allocate.array()
    }

    override fun calculateToText(input: InputStream): String {
        val crc = CRC32C()
        input.foreach { bytes, i ->
            crc.update(bytes, 0, i)
        }
        return crc.value.toString(16).uppercase(Locale.getDefault())
    }
}