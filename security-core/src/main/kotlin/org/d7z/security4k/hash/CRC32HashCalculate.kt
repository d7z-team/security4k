package org.d7z.security4k.hash

import org.d7z.security4k.utils.foreach
import java.io.InputStream
import java.util.Locale
import java.util.zip.CRC32

class CRC32HashCalculate(override val name: String = "CRC32") : BaseHashCalculate {
    override fun calculate(input: InputStream): String {
        val crc = CRC32()
        input.foreach { bytes, i ->
            crc.update(bytes, 0, i)
        }
        return crc.value.toString(16).uppercase(Locale.getDefault())
    }
}
