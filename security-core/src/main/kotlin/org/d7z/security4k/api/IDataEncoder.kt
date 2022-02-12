package org.d7z.security4k.api

import java.io.InputStream
import java.io.OutputStream
import java.nio.charset.Charset

/**
 * 加密数据
 */
interface IDataEncoder {

    /**
     *
     * 加密数据
     *
     * @param plainStream InputStream 明文
     * @param cipherStream OutputStream 密文
     */
    fun encode(plainStream: InputStream, cipherStream: OutputStream)

    /**
     * 加密文字
     *
     * @param plainText String 明文
     * @param charset Charset 编码
     * @return String 密文
     */
    fun encodeText(plainText: String, charset: Charset = Charsets.UTF_8): String
}
