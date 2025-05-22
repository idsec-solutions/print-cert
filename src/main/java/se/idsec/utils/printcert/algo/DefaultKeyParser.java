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

import org.bouncycastle.asn1.ASN1BitString;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/**
 * @author stefan
 */
public class DefaultKeyParser extends PKValueData {

  public DefaultKeyParser(ASN1BitString pkValBitString, AlgorithmIdentifier aid) {
    super(pkValBitString, aid);
  }

  @Override
  protected void parsePk() {
    int keyBits;
    int keydatalen = pkValBitString.getBytes().length;
    keyBits = (keydatalen - 12) * 8;
    if (keydatalen > 127 && keydatalen < 150) {
      keyBits = 1024;
    }
    if (keydatalen > 255 && keydatalen < 280) {
      keyBits = 2048;
    }
    if (keydatalen > 511 && keydatalen < 540) {
      keyBits = 4096;
    }

    keySize = keyBits;
  }

}
