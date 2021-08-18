package com.github.open_edgn.security4k.base64

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.Reader
import java.io.Writer
import java.nio.charset.Charset

object Base64Utils {
    private val impl: IBase64 = StringBase64Format()

    /**
     * Base64 编码
     *
     * @param data String 原始数据
     * @param charset Charset 字符编码
     * @return String 编码后数据
     */
    fun encodeText(data: String, charset: Charset = Charsets.UTF_8, format: Boolean = false): String {
        return encodeBytes(data.toByteArray(charset), format)
    }

    /**
     *
     * Base64 解码
     *
     * @param data String 编码后数据
     * @param charset Charset 解码的字符串编码
     * @return String 解码后数据
     */
    fun decodeText(data: String, charset: Charset = Charsets.UTF_8): String {
        return decodeToBytes(data).toString(charset)
    }

    /**
     *
     * 编码数据为Base64
     *
     */
    fun encodeStream(input: InputStream, output: Writer) {
        impl.encode(input, output)
    }

    fun decodeStream(input: Reader, output: OutputStream) {
        impl.decode(input, output)
    }

    fun encodeBytes(data: ByteArray, format: Boolean = false): String {
        val bf = StringBuilder()
        impl.encode(data.inputStream(), bf)
        return if (format) {
            val out = StringBuilder()
            val line = CharArray(76)
            val reader = bf.toString().reader()
            while (true) {
                val lineSize = reader.read(line)
                if (lineSize <= 0) {
                    break
                }
                out.append(line.concatToString(0, lineSize)).append("\r\n")
            }
            out.trimEnd().toString()
        } else {
            bf.toString()
        }
    }

    fun decodeToBytes(base64Data: String): ByteArray {
        val bf = ByteArrayOutputStream(base64Data.length * (5 / 6))
        impl.decode(base64Data.replace(Regex("([\r\n])"), "").reader(), bf)
        return bf.toByteArray()
    }
}
