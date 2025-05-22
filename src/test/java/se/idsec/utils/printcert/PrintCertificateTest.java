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

package se.idsec.utils.printcert;

import static org.junit.jupiter.api.Assertions.*;

import java.io.File;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Print cert tests
 */
class PrintCertificateTest {
  Logger log = LoggerFactory.getLogger(PrintCertificateTest.class);

  @BeforeAll
  static void init() {
    if (Security.getProvider("BC") == null) {
      Security.insertProviderAt(new BouncyCastleProvider(), 1);
    }
  }

  @Test void testPrintCert() throws Exception {

    testCertificate("root.crt");
    testCertificate("cacert.crt");
    testCertificate("signcert.crt");
    testCertificate("signcert_rsa.crt");
  }

  private void testCertificate(String certResourceName) throws Exception {

    CertificateFactory cf = CertificateFactory.getInstance("X.509");


    PrintCertificate printCertificate = new PrintCertificate(
      (X509Certificate) cf.generateCertificate(PrintCertificateTest.class.getResourceAsStream("/" + certResourceName))
    );

    String certificateString = printCertificate.toString(true, true, true);
    assertEquals("X.509 Certificate {", certificateString.substring(0, certificateString.indexOf("\n")));
    String certificateHtml = printCertificate.toHtml("X.509 Certificate",true, true);
    assertEquals("<table class='table table-sm cert-table-head'", certificateHtml.substring(0, certificateHtml.indexOf(">")));
    log.info("Certificate {} text print:\n{}", certResourceName, certificateString);
    log.info("Certificate {} html print:\n{}", certResourceName, certificateHtml);
  }

}
