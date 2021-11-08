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

import java.util.logging.Level;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 *
 * @author stefan
 */
public class ECKeyParser extends PKValueData{

    public ECKeyParser(ASN1BitString pkValBitString, AlgorithmIdentifier aid) {
        super(pkValBitString, aid);
    }

    @Override
    protected void parsePk() {
        try {
            byte[] bytes = pkValBitString.getBytes();
            //THis assumes that the key is uncompressed. Identified by leading 0x04 byte.
            //Future development may determine more precise key length of compressed keys (0x02 or 0x03).            
            keySize = (bytes.length-1)*4;
        } catch (Exception ex) {
            Logger.getLogger(ECKeyParser.class.getName()).log(Level.SEVERE, null, ex);
        }
        
    }
    
}
