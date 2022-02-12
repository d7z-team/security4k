package org.d7z.security4k.base64

import org.d7z.security4k.api.ITextDataCovert
import org.d7z.security4k.utils.foreach
import java.io.InputStream
import java.io.OutputStream
import java.io.Reader
import java.util.Base64
import kotlin.math.abs

/**
 * Base64 加/解密算法
 */
internal class SimpleBase64Format(
    private val urlMode: Boolean,
    private val mimeMode: Boolean,
) : ITextDataCovert {
    companion object {
        private const val MIME_MAX_LINE = 76
    }

    private val chars by lazy {
        if (urlMode) {
            Base64.getUrlDecoder()
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        } else {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        }
    }
    private val charIndex63 = chars[62]
    private val charIndex64 = chars[63]

    /**
     * 3 * 8 = 4 * 6 = 24
     */
    private val size = 24
    private val bfSize = size / 8
    private val deSize = size / 6

    @Suppress("BlockingMethodInNonBlockingContext")
    override fun encodeStream(input: InputStream, output: Appendable) {
        var bufferSize = 0
        input.foreach(bfSize) { bytes, len ->
            internalEncode(bytes, len) {
                if (mimeMode) {
                    if (bufferSize == MIME_MAX_LINE) {
                        output.append('\r').append('\n')
                        bufferSize = 0
                    }
                    bufferSize++
                }
                output.append(it)
            }
        }
    }

    @Suppress("BlockingMethodInNonBlockingContext")
    private fun internalEncode(bytes: ByteArray, len: Int, output: (Char) -> Unit) {
        val bf = StringBuilder(bfSize * 8)
        for (i in 0 until len) {
            bf.append(
                bytes[i].run {
                    if (this < 0) {
                        abs(256 + this)
                    } else {
                        toInt()
                    }
                }.run {
                    String.format("%-8s", toString(2).reversed())
                        .replace(" ", "0").reversed()
                }
            )
        }
        for (i in 0 until (bfSize - len)) {
            bf.append("00")
        }
        for (index in bf.indices step 6) {
            output(chars[bf.substring(index, index + 6).toInt(2)])
        }
        for (i in 0 until (bfSize - len)) {
            output('=')
        }
    }

    override fun decodeStream(input: Reader, output: OutputStream) {
        val chars = CharArray(deSize)
        var len = 0
        while (true) {
            val buf = input.read() // read a char
            if (buf == -1) {
                internalDecode(chars, output, len)
                break
            } else {
                val toChar = buf.toChar()
                if (len > 3) {
                    internalDecode(chars, output, len)
                    len = 0
                }
                if (toChar != '\r' && toChar != '\n') {
                    chars[len++] = toChar
                }
            }
        }
    }

    private fun internalDecode(chars: CharArray, output: OutputStream, bfSize: Int) {
        val input = StringBuilder()
        val len = bfSize.coerceAtMost(
            when {
                chars[2] == '=' -> 2
                chars[3] == '=' -> 3
                else -> 4
            }
        )
        for (index in 0 until len) {
            val item = when (val value = chars[index]) {
                in 'A'..'Z' -> value - 'A' + 0
                in 'a'..'z' -> value - 'a' + 26
                in '0'..'9' -> value - '0' + 26 + 26
                charIndex63 -> 26 + 26 + 10
                charIndex64 -> 26 + 26 + 10 + 1
                else -> throw IndexOutOfBoundsException("这不是一个base64字段：[$value]")
            }
            val reversed = String.format(
                "%-6s",
                item
                    .toString(2).reversed()
            ).replace(" ", "0").reversed()
            input.append(reversed)
        }
        input.setLength(input.length - (4 - len) * 2)
        for (index in 0 until (input.length) step 8) {
            output.write(input.substring(index, index + 8).toInt(2))
        }
        input.setLength(0)
    }
}
