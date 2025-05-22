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
package se.idsec.utils.printcert.utils;

import se.idsec.utils.printcert.PrintCertificate;
import se.idsec.utils.printcert.data.SubjectAttributeInfo;
import se.idsec.utils.printcert.enums.OidName;
import se.idsec.utils.printcert.enums.SubjectDnType;
import se.idsec.utils.printcert.enums.SupportedExtension;
import se.idsec.utils.printcert.extension.ExtensionInfo;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.EnumMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.PolicyQualifierInfo;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.UserNotice;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509ExtensionUtils;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

/**
 *
 * @author stefan
 */
public class CertUtils {

    private CertUtils() {
    }

    public static List<ExtensionInfo> getExtensions(X509Certificate cert) throws CertificateEncodingException {
        return getExtensions(cert.getEncoded());
    }

    public static List<ExtensionInfo> getExtensions(X509CertificateHolder cert) throws CertificateEncodingException, IOException {
        return getExtensions(cert.getEncoded());
    }

    public static List<ExtensionInfo> getExtensions(byte[] certBytes) {
        List<ExtensionInfo> extList = new ArrayList<>();

        try {
            ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(certBytes));
            ASN1Sequence certSeq = ASN1Sequence.getInstance(din.readObject());
            ASN1Sequence tbsSeq = ASN1Sequence.getInstance(certSeq.getObjectAt(0));

            for (int i = 0; i < tbsSeq.size(); i++) {
                ASN1Encodable certObj = tbsSeq.getObjectAt(i);
                if (certObj instanceof ASN1TaggedObject) {
                    ASN1TaggedObject taggedObj = (ASN1TaggedObject) certObj;
                    if (taggedObj.getTagNo() == 3) {
                        ASN1Sequence extSeq = ASN1Sequence.getInstance(
                          taggedObj.getBaseObject());

                        //Loop through the extensions
                        for (int extIdx = 0; extIdx < extSeq.size(); extIdx++) {
                            ASN1Sequence extInstanceSeq = ASN1Sequence.getInstance(extSeq.getObjectAt(extIdx));
                            ExtensionInfo extInfo = getExtensionInfo(extInstanceSeq, extIdx);
                            extList.add(extInfo);
                        }

                    }
                }
            }

        } catch (Exception e) {
        }

        return extList;
    }

    private static ExtensionInfo getExtensionInfo(ASN1Sequence extInstanceSeq, int seqNo) {
        ExtensionInfo extInfo = new ExtensionInfo(seqNo);
        try {
            ASN1ObjectIdentifier extOid = ASN1ObjectIdentifier.getInstance(extInstanceSeq.getObjectAt(0));
            extInfo.setOid(extOid);
            extInfo.setExtensionType(SupportedExtension.getExtension(extOid));
            int idx = 1;
            //Check criticality

            ASN1Encodable obj2 = extInstanceSeq.getObjectAt(idx);
            if (obj2 instanceof ASN1Boolean) {
                extInfo.setCritical(ASN1Boolean.getInstance(obj2).isTrue());
                idx++;
            }

            ASN1Encodable extDataObj = extInstanceSeq.getObjectAt(idx);
            if (extDataObj != null) {
                extInfo.setExtData(DEROctetString.getInstance(extDataObj).getOctets());
                ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(extInfo.getExtData()));
                extInfo.setExtDataASN1(din.readObject());
            }

        } catch (Exception e) {
        }

        return extInfo;
    }

    public static List<String> getTextLines(String text) {
        List<String> textLines = new ArrayList<String>();

        try {
            BufferedReader input = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(text.getBytes(Charset.forName("UTF-8")))));
            try {
                String line = null;
                while ((line = input.readLine()) != null) {
                    textLines.add(line);
                }
            } finally {
                input.close();
            }
        } catch (IOException ex) {
            Logger.getLogger(CertUtils.class.getName()).warning(ex.getMessage());
        }
        return textLines;
    }

    public static DigestCalculator getSha1DigestCalculator() throws OperatorCreationException {
        return new BcDigestCalculatorProvider().get(new AlgorithmIdentifier(OIWObjectIdentifiers.idSHA1));
    }

    public static X509ExtensionUtils getX509ExtensionUtils() throws OperatorCreationException {
        return new X509ExtensionUtils(getSha1DigestCalculator());
    }

    public static Map<SubjectDnType, SubjectAttributeInfo> getSubjectDnAttributeMap(List<SubjectAttributeInfo> attrList) {
        Map<SubjectDnType, SubjectAttributeInfo> subjectDnAttributeMap = new EnumMap<SubjectDnType, SubjectAttributeInfo>(SubjectDnType.class);
        for (SubjectAttributeInfo attrInfo : attrList) {
            subjectDnAttributeMap.put(attrInfo.getType(), attrInfo);
        }
        return subjectDnAttributeMap;
    }

    public static List<SubjectAttributeInfo> getAttributeInfoList(X500Principal name) {
        List<SubjectAttributeInfo> attrInfoList = new ArrayList<>();
        try {
            ASN1InputStream ain = new ASN1InputStream(name.getEncoded());
            ASN1Sequence nameSeq = ASN1Sequence.getInstance(ain.readObject());

            Iterator<ASN1Encodable> subjDnIt = nameSeq.iterator();
            while (subjDnIt.hasNext()) {
                ASN1Set rdnSet = (ASN1Set) subjDnIt.next();
                Iterator<ASN1Encodable> rdnSetIt = rdnSet.iterator();
                while (rdnSetIt.hasNext()) {
                    ASN1Sequence rdnSeq = (ASN1Sequence) rdnSetIt.next();
                    ASN1ObjectIdentifier rdnOid = (ASN1ObjectIdentifier) rdnSeq.getObjectAt(0);
                    //String oidStr = rdnOid.getId();
                    ASN1Encodable rdnVal = rdnSeq.getObjectAt(1);
                    String rdnValStr = getStringValue(rdnVal);
                    attrInfoList.add(new SubjectAttributeInfo(rdnOid, rdnValStr));
                }
            }

        } catch (Exception e) {
        }
        return attrInfoList;

    }

    private static String getStringValue(ASN1Encodable rdnVal) {
        if (rdnVal instanceof DERUTF8String) {
            DERUTF8String utf8Str = (DERUTF8String) rdnVal;
            return utf8Str.getString();
        }
        if (rdnVal instanceof DERPrintableString) {
            DERPrintableString str = (DERPrintableString) rdnVal;
            return str.getString();
        }
        return rdnVal.toString();
    }

    public static PolicyQualifierInfo getUserNotice(String noticeText) {
        PolicyQualifierInfo pqi = new PolicyQualifierInfo(new ASN1ObjectIdentifier(OidName.usernoticeQualifier.getOid()), new UserNotice(null, noticeText));
        return pqi;
    }

    public static byte[] getPKCS7(List<PrintCertificate> certList) throws CMSException, IOException {
        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        for (PrintCertificate cert : certList) {
            gen.addCertificate(cert);
        }
        CMSSignedData signedData = gen.generate(new CMSProcessableByteArray(null), true);
        return signedData.getEncoded();
    }

    public static SubjectPublicKeyInfo getPublicKeyInfo(PublicKey publicKey) {
        byte[] encoded = publicKey.getEncoded();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(ASN1Sequence.getInstance(encoded));
        return subjectPublicKeyInfo;
    }

}
