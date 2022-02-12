package org.d7z.security4k.api

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.io.Reader
import java.nio.charset.Charset

/**
 * 字符串与原始数据转换抽象
 */
interface ITextDataCovert {
    /**
     * 编码字符串数据为目标字符串
     * @param plain String 原始字符串
     * @param charset Charset 编码方式
     * @return String 目标字符串
     */
    fun encodeText(plain: String, charset: Charset = Charsets.UTF_8): String {
        return encodeBytes(plain.toByteArray(charset))
    }

    /**
     * 解码转换后字符串为原始字符串
     *
     * @param cipher String 转换后字符串
     * @param charset Charset 原始字符串编码方式
     * @return String 原始字符串
     */
    fun decodeText(cipher: String, charset: Charset = Charsets.UTF_8): String {
        return decodeToBytes(cipher).toString(charset)
    }

    /**
     * 编码二进制数据为目标字符串
     *
     * @param raw ByteArray 原始二进制数据
     * @return String 目标字符串
     */
    fun encodeBytes(raw: ByteArray): String {
        val bf = StringBuilder()
        encodeStream(raw.inputStream(), bf)
        return bf.toString()
    }

    /**
     * 解码目标字符串为原始二进制数据
     *
     * @param cipher String 目标字符串
     * @return ByteArray 原始二进制数据
     */
    fun decodeToBytes(cipher: String): ByteArray {
        val bf = ByteArrayOutputStream()
        decodeStream(cipher.replace(Regex("([\r\n])"), "").reader(), bf)
        return bf.toByteArray()
    }

    /**
     *
     * 编码数据为密文
     *
     *
     * @param input InputStream 数据容器
     * @param output Writer 密文接收容器
     */
    fun encodeStream(input: InputStream, output: Appendable)

    /**
     *
     * 将密文解码成原始数据
     *
     * @param input Reader 密文容器
     * @param output OutputStream 原始数据接收容器
     */
    fun decodeStream(input: Reader, output: OutputStream)
}
