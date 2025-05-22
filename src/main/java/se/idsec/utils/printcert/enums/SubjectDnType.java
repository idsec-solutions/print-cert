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
package se.idsec.utils.printcert.enums;

import java.nio.charset.Charset;
import java.nio.charset.CharsetEncoder;
import java.util.Arrays;
import java.util.Objects;
import java.util.logging.Logger;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.style.BCStyle;

/**
 *
 * @author stefan
 */
public enum SubjectDnType {

    cn("Common Name","2.5.4.3"),
    givenName("Given Name","2.5.4.42"),
    surname("Surname","2.5.4.4"),
    personnummer("SE Personnummer","1.2.752.29.4.13"),
    country("Country","2.5.4.6"),
    locality("Locality","2.5.4.7"),
    state("State","2.5.4.8"),
    serialNumber("ID number","2.5.4.5"),
    orgnaizationName("Organization","2.5.4.10"),
    orgnaizationalUnitName("organization Unit","2.5.4.11"),
    organizationIdentifier("Organization ID","2.5.4.97"),
    pseudonym("Pseudonym","2.5.4.65"),
    dnQualifier("DN Qualifier","2.5.4.46"),
    title("Title","2.5.4.12"),
    email("E-Mail", BCStyle.EmailAddress.getId()),
    dateOfBirth("Date of Birth", BCStyle.DATE_OF_BIRTH.getId()),
    domainComponent("Domain Component", BCStyle.DC.getId()),
    description("Description", "2.5.4.13"),
    businessCategory("Business Category", "2.5.4.15"),
    generationQualifier("Generation Qualifier", "2.5.4.44"),
    postalAddress("Postal Address", "2.5.4.16"),
    placeOfBirth("Place of Birth", "1.3.6.1.5.5.7.9.2"),
    gender("Gender", "1.3.6.1.5.5.7.9.3"),
    countryOfCitizenship("Country of Citizenship", "1.3.6.1.5.5.7.9.4"),

    unknown("Unknown",null);

    private static final Logger LOG = Logger.getLogger(SubjectDnType.class.getName());
    private String dispName;
    private String oidString;

    private SubjectDnType(String dispName, String oidString) {
        this.dispName = dispName;
        this.oidString = oidString;
    }


    public static SubjectDnType getNameTypeForOid(ASN1ObjectIdentifier oid) {
        String oidString = oid.getId();
        return getNameTypeForOid(oidString);
    }

    public static SubjectDnType getNameTypeForOid(String oidString) {
        Objects.requireNonNull(oidString, "OID must not be null");
        return Arrays.stream(values())
          .filter(subjectDnType -> oidString.equalsIgnoreCase(subjectDnType.getOidString()))
          .findFirst()
          .orElse(unknown);
    }

    public String getOidString() {
        return oidString;
    }

    public String getDispName() {
        return dispName;
    }

    public AttributeTypeAndValue getAttribute(String value) {
        AttributeTypeAndValue atav = new AttributeTypeAndValue(new ASN1ObjectIdentifier(oidString), getASN1Val(value));
        return atav;
    }

    private ASN1Encodable getASN1Val(String value) {
        boolean isASCII = isStringASCII(value);
        if (!isASCII) {
            if (this.equals(SubjectDnType.serialNumber) || this.equals(SubjectDnType.country)) {
                LOG.warning("Illegal characters for name type");
                return null;
            }
        }
        ASN1Encodable asn1Val;
        if (isASCII || this.equals(SubjectDnType.serialNumber) || this.equals(SubjectDnType.country)) {
            asn1Val = new DERPrintableString(value);
        } else {
            asn1Val = new DERUTF8String(value);
        }
        return asn1Val;
    }

    private boolean isStringASCII(String value) {
        CharsetEncoder asciiEncoder = Charset.forName("US-ASCII").newEncoder();
        return asciiEncoder.canEncode(value);
    }
}
