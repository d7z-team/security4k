package com.github.open_edgn.security4k.asymmetric.universal

import java.io.InputStream
import java.io.OutputStream

/**
 * 加密数据
 */
interface Encoder {

    /**
     *
     * 加密数据
     *
     * @param plainStream InputStream 明文
     * @param cipherStream OutputStream 密文
     */
    fun encode(plainStream: InputStream, cipherStream: OutputStream)
}