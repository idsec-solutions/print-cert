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
package se.idsec.utils.printcert.extension;

import se.idsec.utils.printcert.enums.SupportedExtension;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;

/**
 *
 * @author stefan
 */
public class ExtensionInfo {

    int sequenceNumber;
    boolean critical;
    ASN1ObjectIdentifier oid;
    SupportedExtension extensionType;
    byte[] extData;
    ASN1Primitive extDataASN1;

    public ExtensionInfo(int idx) {
        this.sequenceNumber = idx;
    }

    public SupportedExtension getExtensionType() {
        return extensionType;
    }

    public void setExtensionType(SupportedExtension extensionType) {
        this.extensionType = extensionType;
    }

    public byte[] getExtData() {
        return extData;
    }

    public void setExtData(byte[] extData) {
        this.extData = extData;
    }

    public ASN1Primitive getExtDataASN1() {
        return extDataASN1;
    }

    public void setExtDataASN1(ASN1Primitive extDataASN1) {
        this.extDataASN1 = extDataASN1;
    }

    public int getSequenceNumber() {
        return sequenceNumber;
    }

    public void setSequenceNumber(int sequenceNumber) {
        this.sequenceNumber = sequenceNumber;
    }

    public boolean isCritical() {
        return critical;
    }

    public void setCritical(boolean critical) {
        this.critical = critical;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }

    public void setOid(ASN1ObjectIdentifier oid) {
        this.oid = oid;
    }

}
