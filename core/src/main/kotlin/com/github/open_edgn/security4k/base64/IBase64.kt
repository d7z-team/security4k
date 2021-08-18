package com.github.open_edgn.security4k.base64

import java.io.InputStream
import java.io.OutputStream
import java.io.Reader

/**
 * Base 编、解码抽象接口
 */
internal interface IBase64 {

    /**
     *
     * 编码数据为Base64
     *
     *
     * @param input InputStream 数据容器
     * @param output Writer Base64 接收容器
     */
    fun encode(input: InputStream, output: Appendable)

    /**
     *
     * 将 Base64 解码成原始数据
     *
     * @param input Reader Base64 容器
     * @param output OutputStream 原始数据接收容器
     */
    fun decode(input: Reader, output: OutputStream)
}
