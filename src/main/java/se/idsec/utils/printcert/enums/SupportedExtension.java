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
package se.idsec.utils.printcert.enums;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ocsp.OCSPObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import se.swedenconnect.cert.extensions.AuthnContext;

/**
 *
 * @author stefan
 */
public enum SupportedExtension {
    basicConstraints("Basic Constraints", Extension.basicConstraints),
    authorityInfoAccess("Authority Info Access", Extension.authorityInfoAccess),
    authorityKeyIdentifier("Authority Key Identifier", Extension.authorityKeyIdentifier),
    biometricInfo("Biometric Info", Extension.biometricInfo),
    cRLDistributionPoints("CRL Distribution Point", Extension.cRLDistributionPoints),
    certificateIssuer("Certificate Issuer", Extension.certificateIssuer),
    certificatePolicies("Certificate Policies", Extension.certificatePolicies),
    extendedKeyUsage("Extended Key Usage", Extension.extendedKeyUsage),
    inhibitAnyPolicy("Inhibit Any Policy", Extension.inhibitAnyPolicy),
    issuerAlternativeName("Issuer Alternative Name", Extension.issuerAlternativeName),
    keyUsage("Key Usage", Extension.keyUsage),
    logoType("Logotype", Extension.logoType),
    nameConstraints("Name Constraints", Extension.nameConstraints),
    policyConstraints("Policy Constraints", Extension.policyConstraints),
    policyMappings("Policy Mapping", Extension.policyMappings),
    privateKeyUsagePeriod("Private Key Usage Period", Extension.privateKeyUsagePeriod),
    qCStatements("QC Statements", Extension.qCStatements),
    subjectAlternativeName("Subject Alt Name", Extension.subjectAlternativeName),
    subjectDirectoryAttributes("Subject Directory Attributes", Extension.subjectDirectoryAttributes),
    subjectInfoAccess("Subject Info Access", Extension.subjectInfoAccess),
    subjectKeyIdentifier("Subject Key Identifier", Extension.subjectKeyIdentifier),
    ocspNocheck("OCSP No Check", OCSPObjectIdentifiers.id_pkix_ocsp_nocheck),
    authContext("Authentication Context", AuthnContext.OID),
    signedCertificateTimestampList("Signed Certificate Timestamp List", new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.4.2")),
    netscapeCertType("Netscape Certificate Type", new ASN1ObjectIdentifier("2.16.840.1.113730.1.1")),
    unknown("Unknown", null);

    String name;
    ASN1ObjectIdentifier oid;

    private SupportedExtension(String name, ASN1ObjectIdentifier oid) {
        this.name = name;
        this.oid = oid;
    }

    public String getName() {
        return name;
    }

    public ASN1ObjectIdentifier getOid() {
        return oid;
    }

    public static SupportedExtension getExtension(ASN1ObjectIdentifier oid) {
        return getExtension(oid.getId());
    }

    public static SupportedExtension getExtension(String oid) {
        for (SupportedExtension ext : values()) {
            if (ext.getOid() != null && ext.getOid().getId().equalsIgnoreCase(oid)) {
                return ext;
            }
        }
        return unknown;
    }
}
