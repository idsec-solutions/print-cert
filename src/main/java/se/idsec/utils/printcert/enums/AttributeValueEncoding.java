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
package se.idsec.utils.printcert.enums;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;

/**
 *
 * @author stefan
 */
public enum AttributeValueEncoding {
    PritableString,
    UTF8,
    IA5String;
    
    public ASN1Encodable getEncodedAttributeVal (String value){
        switch(this){
            case PritableString:
                return new DERPrintableString(value);
            case UTF8:
                return new DERUTF8String(value);
            case IA5String:
                return new DERIA5String(value);
            default:
                throw new AssertionError(this.name());            
        }
    }
}
