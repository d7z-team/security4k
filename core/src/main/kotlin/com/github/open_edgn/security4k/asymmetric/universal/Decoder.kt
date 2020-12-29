package com.github.open_edgn.security4k.asymmetric.universal

import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.Charset

/**
 * 解密数据
 */
interface Decoder {
    /**
     *
     * 解密数据
     *
     * @param cipherStream InputStream 密文
     * @param plainStream OutputStream 明文
     */
    fun decode(cipherStream: InputStream, plainStream: OutputStream)

    /**
     * 解密文字字符
     *
     * @param cipherText String 密文
     * @param charset Charset 文字编码
     * @return 明文
     */
    fun decodeText(cipherText: String, charset: Charset = Charsets.UTF_8): String
}