package org.d7z.security4k.base64

import org.d7z.security4k.utils.foreach
import java.io.InputStream
import java.io.OutputStream
import java.io.Reader
import kotlin.math.abs

/**
 * Base64 加/解密算法
 */
internal class StringBase64Format : IBase64 {
    private val chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    /**
     * 3 * 8 = 4 * 6 = 24
     */
    private val size = 24
    private val bfSize = size / 8
    private val deSize = size / 6

    override fun encode(input: InputStream, output: Appendable) {
        input.foreach(bfSize) { bytes, len ->
            internalEncode(bytes, len, output)
        }
    }

    private fun internalEncode(bytes: ByteArray, len: Int, output: Appendable) {
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
            output.append(chars[bf.substring(index, index + 6).toInt(2)])
        }
        for (i in 0 until (bfSize - len)) {
            output.append("=")
        }
    }

    override fun decode(input: Reader, output: OutputStream) {
        val chars = CharArray(deSize)
        while (true) {
            val len = input.read(chars)
            if (len == -1) {
                break
            }
            // 编码后的 base 64 总是 4 的倍数
            internalDecode(chars, output)
        }
    }

    private fun internalDecode(chars: CharArray, output: OutputStream) {
        val input = StringBuilder()
        val len = when {
            chars[2] == '=' -> 2
            chars[3] == '=' -> 3
            else -> 4
        }
        for (index in 0 until len) {
            val item = when (val value = chars[index]) {
                in 'A'..'Z' -> value - 'A' + 0
                in 'a'..'z' -> value - 'a' + 26
                in '0'..'9' -> value - '0' + 26 + 26
                '+' -> 26 + 26 + 10
                '/' -> 26 + 26 + 10 + 1
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
