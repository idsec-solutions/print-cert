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
package se.idsec.utils.printcert.utils;

import se.idsec.utils.printcert.enums.SubjectDnType;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Set;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;

/**
 *
 * @author stefan
 */
public class CertReqUtils {

    public static X500Name getDn(Map<SubjectDnType, String> nameMap) {
        Set<SubjectDnType> keySet = nameMap.keySet();
        RDN[] rdnArray = new RDN[keySet.size()];

        int i = 0;
        for (SubjectDnType nt : keySet) {
            String value = nameMap.get(nt);
            AttributeTypeAndValue atav = nt.getAttribute(value);
            rdnArray[i++] = new RDN(atav);
        }

        X500Name dn = new X500Name(rdnArray);
        return dn;
    }


    /**
     * Generate a KeyPair using the specified algorithm with the given size.
     *
     * @param algorithm the algorithm to use
     * @param bits the length of the key (modulus) in bits
     *
     * @return the KeyPair
     *
     * @exception NoSuchAlgorithmException if no KeyPairGenerator is available
     * for the requested algorithm
     */
    public static KeyPair generateKeyPair(String algorithm, int bits)
            throws NoSuchAlgorithmException {

        KeyPair kp = null;
        KeyPairGenerator generator = null;
        generator = KeyPairGenerator.getInstance(algorithm);
        generator.initialize(bits);
        kp = generator.generateKeyPair();
        return kp;
    }

}
