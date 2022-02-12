package org.d7z.security4k.api

import java.io.InputStream
import java.math.BigInteger

interface IStreamCalculate {

    /**
     * 计算 Stream 的校验值并返回唯一字符串结果
     * @param input InputStream 被计算的流
     * @return String 计算结果
     */
    fun calculateToText(input: InputStream): String {
        return BigInteger(1, calculateToBinary(input)).toString(16).uppercase()
    }

    /**
     * 计算 Stream 的校验值并返回唯一二进制结果
     * @param input InputStream 被计算的流
     * @return ByteArray 计算结果
     */
    fun calculateToBinary(input: InputStream): ByteArray
}
