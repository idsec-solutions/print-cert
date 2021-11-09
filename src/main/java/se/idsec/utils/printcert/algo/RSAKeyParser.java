/*
 * Copyright (c) 2021. IDsec Solutions AB (IDsec)
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

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author stefan
 */
public class RSAKeyParser extends PKValueData {

    public RSAKeyParser(ASN1BitString pkValBitString, AlgorithmIdentifier aid) {
        super(pkValBitString, aid);
    }

    @Override
    protected void parsePk() {
        try {
            ASN1InputStream pkIn = new ASN1InputStream(pkValBitString.getOctets());
            ASN1Sequence pkValSeq = ASN1Sequence.getInstance(pkIn.readObject());
            ASN1Integer modulus = ASN1Integer.getInstance(pkValSeq.getObjectAt(0));
            ASN1Integer.getInstance(pkValSeq.getObjectAt(1));
            keySize = modulus.getValue().bitLength();            
        } catch (Exception e) {
            keySize = 0;
        }

    }

}
