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

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package se.idsec.utils.printcert.algo;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * @author stefan
 */
public enum PublicKeyType {
    rsa("RSA", "1.2.840.113549.1.1.1"),
    rsassa_pss("RSASSA-PSS","1.2.840.113549.1.1.10"),
    ecdsa("EC", "1.2.840.10045.2.1"),
    dsa("DSA", "1.2.840.10040.4.1"),
    dh("DH", "1.2.840.10046.2.1"),
    unknown("Unknown", null);

    String name;
    String oid;

    private PublicKeyType(String name, String oid) {
        this.name = name;
        this.oid = oid;
    }

    public String getName() {
        return name;
    }

    public String getOid() {
        return oid;
    }

    public static PublicKeyType getKeyType(ASN1ObjectIdentifier oid) {
        return getKeyType(oid.getId());
    }

    public static PublicKeyType getKeyType(String oid) {
        for (PublicKeyType pkType : values()) {
            if (pkType.getOid().equalsIgnoreCase(oid)) {
                return pkType;
            }
        }
        return unknown;
    }

}
