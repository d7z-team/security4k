package com.github.open_edgn.security4k.asymmetric.rsa

import com.github.open_edgn.security4k.asymmetric.universal.Decoder
import com.github.open_edgn.security4k.asymmetric.universal.Encoder

abstract class RSA : Decoder, Encoder {

    protected val transformation: String = "RSA"
    private val algorithm = "RSA/ECB/PKCS1Padding"

    fun doFinal() {
    }

}