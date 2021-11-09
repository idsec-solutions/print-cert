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
package se.idsec.utils.printcert.data;

import se.idsec.utils.printcert.enums.OidName;
import se.idsec.utils.printcert.enums.SubjectDnType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/**
 *
 * @author stefan
 */
public class SubjectAttributeInfo {
    SubjectDnType type;
    ASN1ObjectIdentifier oid;
    String dispName;
    String value;

    public SubjectAttributeInfo(ASN1ObjectIdentifier oid, String value) {
        this.oid = oid;
        this.value = value;
        
        type = SubjectDnType.getNameTypeForOid(oid);
        if (!type.equals(SubjectDnType.unknown)){
            dispName = type.getDispName();
        } else {
            dispName = OidName.getName(oid.getId());
        }        
    }

    public SubjectAttributeInfo() {
    }

    public SubjectDnType getType() {
        return type;
    }

    public void setType(SubjectDnType type) {
        this.type = type;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }

    public void setOid(ASN1ObjectIdentifier oid) {
        this.oid = oid;
    }

    public String getDispName() {
        return dispName;
    }

    public void setDispName(String dispName) {
        this.dispName = dispName;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
    
    
}
