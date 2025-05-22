/*
 * Copyright 2021-2025 IDsec Solutions AB
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package se.idsec.utils.printcert.algo;

import java.io.IOException;
import java.security.PublicKey;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author stefan
 */
public class PublicKeyData {

    PublicKey publicKey;
    String algorithm;
    ASN1ObjectIdentifier algorithmOid;
    PublicKeyType pkType;
    PKValueData pkValData;

    public PublicKeyData(PublicKey publicKey) {
        this.publicKey = publicKey;
        parse();
    }

    private void parse() {
        algorithm = publicKey.getAlgorithm();

        try {
            ASN1InputStream ain = new ASN1InputStream(publicKey.getEncoded());
            ASN1Sequence pkSeq = ASN1Sequence.getInstance(ain.readObject());
            AlgorithmIdentifier algId = AlgorithmIdentifier.getInstance(pkSeq.getObjectAt(0));
            algorithmOid = algId.getAlgorithm();
            ASN1BitString pkBits = ASN1BitString.getInstance(pkSeq.getObjectAt(1));

            pkType = PublicKeyType.getKeyType(algorithmOid);
            pkValData = getPKValueData(pkBits,algId);
        } catch (IOException ex) {
            Logger.getLogger(PublicKeyData.class.getName()).log(Level.WARNING, null, ex);
        }
    }

    private PKValueData getPKValueData(ASN1BitString pkBits, AlgorithmIdentifier algId) {
        switch (pkType){
            case rsa:
                return new RSAKeyParser(pkBits, algId);
            case ecdsa:
                return new ECKeyParser(pkBits, algId);
            default:
                return new DefaultKeyParser(pkBits, algId);
        }
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public ASN1ObjectIdentifier getAlgorithmOid() {
        return algorithmOid;
    }

    public PublicKeyType getPkType() {
        return pkType;
    }

    public PKValueData getPkValData() {
        return pkValData;
    }

    public int getKeySize(){
        return pkValData.getKeySize();
    }

}
