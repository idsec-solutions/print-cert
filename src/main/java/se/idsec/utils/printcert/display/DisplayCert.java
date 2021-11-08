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
package se.idsec.utils.printcert.display;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.asn1.x509.PrivateKeyUsagePeriod;
import org.bouncycastle.asn1.x509.qualified.BiometricData;
import org.bouncycastle.util.encoders.Hex;
import se.idsec.utils.printcert.PrintCertificate;
import se.idsec.utils.printcert.data.SubjectAttributeInfo;
import se.idsec.utils.printcert.display.html.TableElement;
import se.idsec.utils.printcert.enums.OidName;
import se.idsec.utils.printcert.enums.SubjectDnType;
import se.idsec.utils.printcert.enums.SupportedExtension;
import se.idsec.utils.printcert.extension.ExtensionInfo;
import se.idsec.utils.printcert.utils.CertUtils;
import se.idsec.x509cert.extensions.*;
import se.idsec.x509cert.extensions.data.MonetaryValue;
import se.idsec.x509cert.extensions.data.PDSLocation;
import se.idsec.x509cert.extensions.data.SemanticsInformation;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.AttributeMapping;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.AuthContextInfo;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.IdAttributes;
import se.swedenconnect.schemas.cert.authcont.saci_1_0.SAMLAuthContext;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * @author stefan
 */
public class DisplayCert {

  /**
   * The default cert display table class names for html print.
   */
  public static final CertTableClasses DEF_TABLE_CLASSES = new CertTableClasses(
    "table table-sm cert-table",
    "table table-sm cert-table-head",
    "subjectDNTable",
    new String[] { "certTableHeadRow", "certTableHead" },
    new String[] { "certTableValueRow", "certTableParam", "cerTableValue" },
    new String[] { "certTableExtHeadRow", "certTableExtHead" },
    new String[] { "certTableExtValueRow", "certTableExtParam", "cerTableExtValue" },
    new String[] { "certTableExtSubValueRow", "certTableExtSubParam", "cerTableExtSubValue" },
    new String[] { "certTableValueRow", "certTableExtParam", "cerTableExtValue" },
    new String[] { "certTableValueRow", "certTableExtParam", "cerTableMonospaceVal" },
    new String[] { "subjectDNRow", "subjectDNParam", "subjectDNVal" }
  );
  private static final String[] generalNameTagText = new String[] {
    "Other Name",
    "E-Mail",
    "DNS",
    "x400Address",
    "Directory Name",
    "EDI Party Name",
    "URI",
    "IP Address",
    "Registered ID" };
  private static final String[] verboseParams = new String[] {
    "modulus",
    "public x coord",
    "public y coord"
  };

  public static String certToDisplayString(PrintCertificate cert, boolean monospace, boolean verbose, boolean decode) {
    StringBuilder b = new StringBuilder();
    List<UnitDisplayData> dispList = new ArrayList<>();
    dispList.add(getCertFieldDispData(cert, verbose, decode, false));
    List<ExtensionInfo> extensionInfoList = cert.getExtensionInfoList();
    for (int i = 0; i < extensionInfoList.size(); i++) {
      try {
        UnitDisplayData extensionPrintData = getExtensionPrintData(extensionInfoList.get(i), i);
        dispList.add(extensionPrintData);
      }
      catch (IOException ex) {
        Logger.getLogger(DisplayCert.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    dispList.add(getCertSignData(cert, verbose));

    b.append("X.509 Certificate {\n");
    for (UnitDisplayData dispData : dispList) {
      b.append(getTextDisplay(dispData, monospace)).append("\n");
    }
    b.append("}");

    return b.toString();

  }

  public static String certToHtmlString(PrintCertificate cert, String heading, boolean verbose) {
    return certToHtmlString(cert, heading, DEF_TABLE_CLASSES, verbose, true);
  }

  public static String certToHtmlString(PrintCertificate cert, String heading, boolean verbose, boolean decode) {
    return certToHtmlString(cert, heading, DEF_TABLE_CLASSES, verbose, decode);
  }

  public static String certToHtmlString(PrintCertificate cert, String heading, CertTableClasses tableClasses, boolean verbose,
    boolean decode) {
    List<UnitDisplayData> dispList = new ArrayList<>();
    dispList.add(getCertFieldDispData(cert, verbose, decode, true));
    List<ExtensionInfo> extensionInfoList = cert.getExtensionInfoList();
    for (int i = 0; i < extensionInfoList.size(); i++) {
      try {
        UnitDisplayData extensionPrintData = getExtensionPrintData(extensionInfoList.get(i), i);
        dispList.add(extensionPrintData);
      }
      catch (IOException ex) {
        Logger.getLogger(DisplayCert.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    dispList.add(getCertSignData(cert, verbose));
    return getHtmlDisplay(dispList, heading, tableClasses);

  }

  private static UnitDisplayData getExtensionPrintData(ExtensionInfo extInfo, int idx) throws IOException {
    return getExtensionPrintData(extInfo.getOid(), extInfo.getExtDataASN1(), extInfo.isCritical(), extInfo.getExtData(), idx);
  }

  private static UnitDisplayData getExtensionPrintData(ASN1ObjectIdentifier oid, ASN1Primitive extDataASN1, boolean critical, byte[] bytes,
    int idx) throws IOException {
    SupportedExtension extension = SupportedExtension.getExtension(oid);
    List<String[]> da = new ArrayList<>();

    switch (extension) {
    case basicConstraints:
      BasicConstraints ext = BasicConstraints.getInstance(extDataASN1);
      da.add(new String[] { "CA", String.valueOf(ext.isCA()) });
      if (ext.getPathLenConstraint() != null) {
        da.add(new String[] { "PathLen", ext.getPathLenConstraint().toString() });
      }
      return new UnitDisplayData(extension, idx, critical, da);
    case authorityInfoAccess:
      AuthorityInformationAccess aia = AuthorityInformationAccess.getInstance(extDataASN1);
      AccessDescription[] aiadescArray = aia.getAccessDescriptions();
      if (aiadescArray != null) {
        for (int i = 0; i < aiadescArray.length; i++) {
          da.add(new String[] { "accessMethod" + getIndexStr(i), OidName.getName(aiadescArray[i].getAccessMethod().getId()) });
          da.add(new String[] { "  accessLocation", getGeneralNameStr(aiadescArray[i].getAccessLocation()) });
        }
      }
      return new UnitDisplayData(extension, idx, critical, da);
    //return new UnitDisplayData(extension, idx, critical, new AuthorityInfoAccessExtension(critical, bytes).toString(), true);
    case authorityKeyIdentifier:
      AuthorityKeyIdentifier aki = AuthorityKeyIdentifier.getInstance(extDataASN1);
      byte[] keyIdentifier = aki.getKeyIdentifier();
      BigInteger authorityCertSerialNumber = aki.getAuthorityCertSerialNumber();
      GeneralNames authorityCertIssuer = aki.getAuthorityCertIssuer();
      if (keyIdentifier != null) {
        da.add(new String[] { "Key identifier", byteArrayToHexString(keyIdentifier) });
      }
      if (authorityCertIssuer != null) {
        da.add(new String[] { "Cert Issuer", getGeneralNamesString(authorityCertIssuer) });
      }
      if (authorityCertSerialNumber != null) {
        da.add(new String[] { "Cert serial", authorityCertSerialNumber.toString(16) });
      }
      return new UnitDisplayData(extension, idx, critical, da);
    //return new UnitDisplayData(extension, idx, critical, new AuthorityKeyIdentifierExtension(critical, bytes).toString(), true);
    case biometricInfo:
      BiometricInfo biometricInfo = BiometricInfo.getInstance(extDataASN1);
      List<BiometricData> biometricDataList = biometricInfo.getBiometricDataList();
      for (int bdIdx = 0; bdIdx < biometricDataList.size(); bdIdx++) {
        BiometricData biometricData = biometricDataList.get(bdIdx);

        da.add(new String[] { "Biometric data" + getIndexStr(bdIdx),
          "Type: " + BiometricInfo.getTypeString(biometricData.getTypeOfBiometricData()) });
        da.add(new String[] { "  Hash algoritm", biometricData.getHashAlgorithm().getAlgorithm().getId() });
        da.add(new String[] { "  Hash value", Hex.toHexString(biometricData.getBiometricDataHash().getOctets()) });
        if (biometricData.getSourceDataUri() != null) {
          da.add(new String[] { "  Source UIR", biometricData.getSourceDataUri().getString() });
        }
      }
      return new UnitDisplayData(extension, idx, critical, da);
    case cRLDistributionPoints:
      CRLDistPoint crldp = CRLDistPoint.getInstance(extDataASN1);
      DistributionPoint[] distributionPoints = crldp.getDistributionPoints();
      if (distributionPoints != null) {
        for (int dpIdx = 0; dpIdx < distributionPoints.length; dpIdx++) {
          DistributionPointName dpn = distributionPoints[dpIdx].getDistributionPoint();
          try {
            GeneralNames dpGns = (GeneralNames) dpn.getName();
            GeneralName[] names = dpGns.getNames();
            for (int i = 0; i < names.length; i++) {
              da.add(new String[] { "DistributionPoint" + getIndexStr(dpIdx), getGeneralNameStr(names[i]) });
            }
          }
          catch (Exception ex) {
          }
        }
      }
      return new UnitDisplayData(extension, idx, critical, da);
    case certificateIssuer:
      return new UnitDisplayData(extension, idx, critical, null, false);
    case certificatePolicies:
      CertificatePolicies cp = CertificatePolicies.getInstance(extDataASN1);
      getPolicyText(cp, da);
      return new UnitDisplayData(extension, idx, critical, da);
    //return new UnitDisplayData(extension, idx, critical, new CertificatePoliciesExtension(critical, bytes).toString(), true);
    case extendedKeyUsage:
      ExtendedKeyUsage eku = ExtendedKeyUsage.getInstance(extDataASN1);
      KeyPurposeId[] usages = eku.getUsages();
      if (usages != null) {
        for (int i = 0; i < usages.length; i++) {
          da.add(new String[] { "KeyPurposeId " + getIndexStr(i), OidName.getName(usages[i].getId()) });
        }
      }
      return new UnitDisplayData(extension, idx, critical, da);
    //return new UnitDisplayData(extension, idx, critical, new ExtendedKeyUsageExtension(critical, bytes).toString(), true);
    case issuerAlternativeName:
      GeneralNames ian = GeneralNames.getInstance(extDataASN1);
      if (ian != null) {
        getAltNameExtensionDisp(ian, da);
      }
      return new UnitDisplayData(extension, idx, critical, da);
    case keyUsage:
      KeyUsage keyUsage = KeyUsage.getInstance(extDataASN1);
      getKeyUsageText(keyUsage, da);
      return new UnitDisplayData(extension, idx, critical, da);
    case netscapeCertType:
      KeyUsage nsct = KeyUsage.getInstance(extDataASN1);
      getNetscapeCertTypeText(nsct, da);
      return new UnitDisplayData(extension, idx, critical, da);
    case logoType:
      return new UnitDisplayData(extension, idx, critical, null, false);
    case inhibitAnyPolicy:
      getInhibitAnyPolicyText(InhibitAnyPolicy.getInstance(bytes), da);
      return new UnitDisplayData(extension, idx, critical, da);
    case nameConstraints:
      getNameConstraintsText(NameConstraints.getInstance(bytes), da);
      return new UnitDisplayData(extension, idx, critical, da);
    case policyConstraints:
      getPolicyConstraintsText(PolicyConstraints.getInstance(bytes), da);
      return new UnitDisplayData(extension, idx, critical, da);
    case policyMappings:
      getPolicyMappingsText(PolicyMappings.getInstance(bytes), da);
      return new UnitDisplayData(extension, idx, critical, da);
    case privateKeyUsagePeriod:
      PrivateKeyUsagePeriod pkup = PrivateKeyUsagePeriod.getInstance(extDataASN1);
      if (pkup.getNotBefore() != null) {
        da.add(new String[] { "NotBefore ", pkup.getNotBefore().toString() });
      }
      if (pkup.getNotAfter() != null) {
        da.add(new String[] { "NotAfter ", pkup.getNotAfter().toString() });
      }
      return new UnitDisplayData(extension, idx, critical, da);
    case qCStatements:
      //b.append("ObjectId: ").append(oid.getId()).append(" Criticality=").append(critical).append("\n");
      QCStatements qcstatements = QCStatements.getInstance(extDataASN1);
      getQcStatementsDisp(qcstatements, da);
      return new UnitDisplayData(extension, idx, critical, da);
    //b.append(QCStatementsExt.getInstance(extDataASN1).toString());
    //return new UnitDisplayData(extension, idx, critical, b.toString(), false);
    case subjectAlternativeName:
      GeneralNames san = GeneralNames.getInstance(extDataASN1);
      if (san != null) {
        getAltNameExtensionDisp(san, da);
      }
      return new UnitDisplayData(extension, idx, critical, da);
    case subjectDirectoryAttributes:
      return new UnitDisplayData(extension, idx, critical, SubjectDirectoryAttributes.getInstance(extDataASN1).toString(), true);
    case subjectInfoAccess:
      SubjectInformationAccess sia = SubjectInformationAccess.getInstance(extDataASN1);
      AccessDescription[] siadescArray = sia.getAccessDescriptions();
      if (siadescArray != null) {
        for (int i = 0; i < siadescArray.length; i++) {
          da.add(new String[] { "accessMethod" + getIndexStr(i), OidName.getName(siadescArray[i].getAccessMethod().getId()) });
          da.add(new String[] { "  accessLocation", getGeneralNameStr(siadescArray[i].getAccessLocation()) });
        }
      }
      return new UnitDisplayData(extension, idx, critical, da);
    case subjectKeyIdentifier:
      SubjectKeyIdentifier ski = SubjectKeyIdentifier.getInstance(extDataASN1);
      byte[] skeyIdentifier = ski.getKeyIdentifier();
      if (skeyIdentifier != null) {
        da.add(new String[] { "Key identifier", byteArrayToHexString(skeyIdentifier) });
      }
      return new UnitDisplayData(extension, idx, critical, da);
    //return new UnitDisplayData(extension, idx, critical, new SubjectKeyIdentifierExtension(critical, bytes).toString(), true);
    case ocspNocheck:
      return new UnitDisplayData(extension, idx, critical, da);
      //return new UnitDisplayData(extension, idx, critical, new OCSPNoCheckExtension(critical, bytes).toString(), true);
    case authContext:
      AuthnContext authCont = AuthnContext.getInstance(extDataASN1);
      getAuthnContextDisp(authCont, da);
      return new UnitDisplayData(extension, idx, critical, da);
    //b.append(AuthnContext.getInstance(extDataASN1));
    //return new UnitDisplayData(extension, idx, critical, b.toString(), false);
    case unknown:
      UnitDisplayData unknownData = new UnitDisplayData(UnitType.extension);
      unknownData.setCriticality(critical);
      unknownData.setId(oid.getId());
      unknownData.setSequence(idx);
      unknownData.setName("Unkown extension");
      unknownData.setStructured(false);
      unknownData.setFreeText("Unknown data structure with " + String.valueOf(bytes.length) + " bytes of data");
      return unknownData;
    case signedCertificateTimestampList:
      da.add(new String[] { "SignedTimeStampList", String.valueOf(bytes.length) + " bytes of data" });
      return new UnitDisplayData(extension, idx, critical, da);
    default:
      throw new AssertionError(extension.name());

    }
  }

  private static UnitDisplayData getCertFieldDispData(PrintCertificate cert, boolean verbose, boolean decode, boolean html) {
    UnitDisplayData udd = new UnitDisplayData(UnitType.certFields);
    udd.setStructured(true);
    List<String[]> dataArray = new ArrayList<>();
    dataArray.add(new String[] { "Version", String.valueOf(cert.getVersion()) });
    dataArray.add(new String[] { "Serial number", cert.getSerialNumber().toString(16) });
    dataArray.add(new String[] { "Issuer", getCertNameFieldPrint(cert.getIssuer(), decode, html) });
    dataArray.add(new String[] { "Not valid before", cert.getNotBefore().toString() });
    dataArray.add(new String[] { "Not valid after", cert.getNotAfter().toString() });
    dataArray.add(new String[] { "Subject", getCertNameFieldPrint(cert.getSubject(), decode, html) });

    //Extract public key info from oiginal print.
    List<String> textLines = CertUtils.getTextLines(cert.toOriginalString());
    boolean pkStart = false, pkEnd = false;
    for (String line : textLines) {
      if (line.trim().startsWith("Public Key:")) {
        pkStart = true;
      }
      if (pkStart && line.trim().length()==0) {
        pkEnd = true;
      }
      if (pkStart && !pkEnd) {
        line = line.trim();
        String[] split = line.split(":");
        int len = split.length;
        if (len > 1) {
          if (verbose || !isVerbose(split[0])) {
            if (len == 2){
              dataArray.add(new String[] { split[0].trim(), split[1].trim() });
            } else {
              dataArray.add(new String[] { line.substring(0, line.indexOf(":")), line.substring(line.indexOf(":")+2) });
            }
          }
        }
        if (len == 1) {
          dataArray.add(new String[] { "parameter", line.trim() });
        }
      }
    }

    try {
      //Add fingerprint
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] digest = md.digest(cert.getEncoded());
      //dataArray.add(new String[] { "", "" });
      dataArray.add(new String[] { "SHA1 Fingerprint", byteArrayToHexString(digest) });

    }
    catch (NoSuchAlgorithmException ex) {
      Logger.getLogger(DisplayCert.class.getName()).log(Level.SEVERE, null, ex);
    }

    udd.setDataArray(dataArray);
    return udd;
  }

  private static boolean isVerbose(String string) {
    for (String verboseStr : verboseParams) {
      if (string.equalsIgnoreCase(verboseStr)) {
        return true;
      }
    }
    return false;
  }

  private static UnitDisplayData getCertSignData(PrintCertificate cert, boolean verbose) {
    List<String> textLines = CertUtils.getTextLines(cert.toOriginalString());
    UnitDisplayData dispData = new UnitDisplayData(UnitType.signature);
    StringBuilder b = new StringBuilder();
    boolean sigStart = false;
    int i = 0;
    int algoStart = -1;
    List<String[]> da = new ArrayList<>();
    // Loop through all cert lines
    while (i < textLines.size()) {
      String line = textLines.get(i);
      if (line.trim().startsWith("Signature Algorithm:")) {
        algoStart = i;
        break;
      }
      i++;
    }


    boolean display=false;
    if (verbose) {
      String sigAlgo = "";
      String sigValue = "";
      if (algoStart > -1) {
        for (int j = algoStart; j < textLines.size(); j++) {
          String line = textLines.get(j);
          if (line.trim().toLowerCase().startsWith("extensions")){
            break;
          }
          if (j == algoStart){
            sigAlgo = line.trim().substring(21);
          }
          if (j == algoStart+1){
            b.append(line.trim().substring(11));
          }
          if (j > algoStart +1){
            b.append(line.trim());
          }

        }
        dispData.setStructured(true);
        da.add(new String[] { "Signature Algorithm", sigAlgo});
        da.add(new String[] { "Signature", b.toString()});
        dispData.setDataArray(da);
        display=true;
      }
    }
    else {
      if (algoStart > -1) {
        try {
          da.add(new String[] { "Algorithm", textLines.get(algoStart).trim().substring(20).trim()});
          dispData.setStructured(true);
          dispData.setDataArray(da);
          display=true;
        } catch (Exception ex){
          Logger.getLogger(DisplayCert.class.getName()).fine("Failed to parse Algorithm data in certificate");
        }
      }
    }

    if (!display){
      dispData.setStructured(false);
      dispData.setFreeText("Unable to parse algorithm and signature data");
    }

    return dispData;

  }

  private static String getTextDisplay(UnitDisplayData dispData, boolean monospace) {
    StringBuilder b = new StringBuilder();
    int maxLen = -1;
    List<String[]> dataArray = dispData.getDataArray();
    if (dispData.isStructured() && monospace) {
      maxLen = getMaxLen(dispData.getDataArray());
    }

    UnitType type = dispData.getType();
    switch (type) {
    case certFields:
      for (String[] strArray : dataArray) {
        if (strArray[0].length() + strArray[1].length() > 0) {
          b.append(strArray[0]).append(getSpc(maxLen - strArray[0].length())).append(": ").append(strArray[1]).append("\n");
        }
        else {
          b.append("\n");
        }
      }
      break;
    case extension:
      b.append("Extension ").append(dispData.getSequence() + 1).append(":   ");
      if (!dispData.isHasPrefix()) {
        b.append(dispData.isCriticality() ? "critical   " : "not critical   ");
        b.append(dispData.getName()).append(" (").append(dispData.getId()).append(")\n");
      }
      if (dispData.isStructured()) {
        for (String[] strArray : dataArray) {
          if (strArray[0].length() + strArray[1].length() > 0) {
            b.append("  ").append(strArray[0]).append(getSpc(maxLen - strArray[0].length())).append(": ").append(strArray[1]).append("\n");
          }
          else {
            b.append("\n");
          }
        }
      }
      else {
        b.append("  ").append(dispData.getFreeText().trim()).append("\n");
      }
      break;
    case signature:
      b.append("Certificate Signature:\n");
      if (dispData.isStructured()) {
        for (String[] strArray : dataArray) {
          if (strArray[0].length() + strArray[1].length() > 0) {
            b.append(strArray[0]).append(getSpc(maxLen - strArray[0].length())).append(": ").append(strArray[1]).append("\n");
          }
          else {
            b.append("\n");
          }
        }
      }
      else {
        b.append(dispData.getFreeText().trim()).append("\n");
      }
      break;
    default:
      throw new AssertionError(type.name());

    }
    return b.toString();

  }

  public static String byteArrayToHexString(byte[] b) {
    String result = "";
    for (int i = 0; i < b.length; i++) {
      result += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
      if ((i + 1) < b.length) {
        result += ":";
      }
    }
    return result;
  }

  private static int getMaxLen(List<String[]> dataArray) {
    int max = -1;
    for (String[] strArray : dataArray) {
      int arraySize = strArray.length;
      if (arraySize > 0) {
        String str = strArray[0];
        if (str.length() > max) {
          max = str.length();
        }
      }
    }
    return max;
  }

  private static String getSpc(int len) {
    String spcStr = "";
    for (int i = 0; i < len; i++) {
      spcStr += " ";
    }
    return spcStr;
  }

  private static String getGeneralNamesString(GeneralNames genNames) {
    GeneralName[] names = genNames.getNames();
    StringBuilder b = new StringBuilder();
    b.append("GeneralNames {");
    for (int i = 0; i < names.length; i++) {
      b.append(getGeneralNameStr(names[i]));
      if (i + 1 < names.length) {
        b.append(" | ");
      }
    }
    b.append("}");
    return b.toString();
  }

  public static String getGeneralNameStr(GeneralName generalName) {
    if (generalName == null) {
      return "null";
    }
    String toString = generalName.toString();
    try {
      int tagNo = Integer.valueOf(toString.substring(0, toString.indexOf(":")));
      return generalNameTagText[tagNo] + toString.substring(toString.indexOf(":"));

    }
    catch (Exception e) {
      return toString;
    }
  }

  private static void getPolicyText(CertificatePolicies cp, List<String[]> da) {
    try {
      ASN1InputStream din = new ASN1InputStream(new ByteArrayInputStream(cp.getEncoded()));
      ASN1Sequence polInfoSeq = ASN1Sequence.getInstance(din.readObject());
      for (int i = 0; i < polInfoSeq.size(); i++) {
        ASN1Sequence polSeq = ASN1Sequence.getInstance(polInfoSeq.getObjectAt(i));
        ASN1ObjectIdentifier policyId = ASN1ObjectIdentifier.getInstance(polSeq.getObjectAt(0));
        da.add(new String[] { "certificatePolicy" + getIndexStr(i), OidName.getName(policyId.getId()) });
        if (polSeq.size() > 1) {
          ASN1Sequence qualSeq = ASN1Sequence.getInstance(polSeq.getObjectAt(1));
          for (int qualifierIdx = 0; qualifierIdx < qualSeq.size(); qualifierIdx++) {
            ASN1Sequence qualInfoSeq = ASN1Sequence.getInstance(qualSeq.getObjectAt(qualifierIdx));
            ASN1ObjectIdentifier qualifierId = ASN1ObjectIdentifier.getInstance(qualInfoSeq.getObjectAt(0));
            da.add(new String[] { "  qualifier" + getIndexStr(qualifierIdx), OidName.getName(qualifierId.getId()) });
            if (qualifierId.getId().equalsIgnoreCase(OidName.cpsQualifier.getOid())) {
              da.add(new String[] { "  - CPS URI", DERIA5String.getInstance(qualInfoSeq.getObjectAt(1)).getString() });
            }
            if (qualifierId.getId().equalsIgnoreCase(OidName.usernoticeQualifier.getOid())) {
              da.add(new String[] { "  - User Notice", qualInfoSeq.getObjectAt(1).toString() });
            }
          }
        }

      }

    }
    catch (IOException ex) {
      Logger.getLogger(DisplayCert.class.getName()).log(Level.SEVERE, null, ex);
    }

  }

  private static void getKeyUsageText(KeyUsage keyUsage, List<String[]> da) {
    da.add(new String[] { "Usage", getKeyUsageText(keyUsage) });

  }

  public static String getKeyUsageText(KeyUsage keyUsage) {
    List<String> usagesList = new ArrayList<>();
    StringBuilder b = new StringBuilder();
    if (keyUsage.hasUsages(KeyUsage.digitalSignature)) {
      usagesList.add("digitalSignature");
    }
    if (keyUsage.hasUsages(KeyUsage.nonRepudiation)) {
      usagesList.add("nonRepudiation");
    }
    if (keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
      usagesList.add("keyEncipherment");
    }
    if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) {
      usagesList.add("dataEncipherment");
    }
    if (keyUsage.hasUsages(KeyUsage.keyAgreement)) {
      usagesList.add("keyAgreement");
    }
    if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
      usagesList.add("keyCertSign");
    }
    if (keyUsage.hasUsages(KeyUsage.cRLSign)) {
      usagesList.add("cRLSign");
    }
    if (keyUsage.hasUsages(KeyUsage.encipherOnly)) {
      usagesList.add("encipherOnly");
    }
    if (keyUsage.hasUsages(KeyUsage.decipherOnly)) {
      usagesList.add("decipherOnly");
    }
    for (int i = 0; i < usagesList.size(); i++) {
      b.append(usagesList.get(i));
      if (i + 1 < usagesList.size()) {
        b.append(" | ");
      }
    }
    return b.toString();
  }

  private static void getNetscapeCertTypeText(KeyUsage keyUsage, List<String[]> da) {
    List<String> usagesList = new ArrayList<>();
    StringBuilder b = new StringBuilder();
    if (keyUsage.hasUsages(KeyUsage.digitalSignature)) {
      usagesList.add("SSL Client");
    }
    if (keyUsage.hasUsages(KeyUsage.nonRepudiation)) {
      usagesList.add("SSL Server");
    }
    if (keyUsage.hasUsages(KeyUsage.keyEncipherment)) {
      usagesList.add("S/MIME");
    }
    if (keyUsage.hasUsages(KeyUsage.dataEncipherment)) {
      usagesList.add("Object-signing");
    }
    if (keyUsage.hasUsages(KeyUsage.keyAgreement)) {
      usagesList.add("Reserved");
    }
    if (keyUsage.hasUsages(KeyUsage.keyCertSign)) {
      usagesList.add("SSL-CA");
    }
    if (keyUsage.hasUsages(KeyUsage.cRLSign)) {
      usagesList.add("S/MIME CA");
    }
    if (keyUsage.hasUsages(KeyUsage.encipherOnly)) {
      usagesList.add("Object-signing CA");
    }
    for (int i = 0; i < usagesList.size(); i++) {
      b.append(usagesList.get(i));
      if (i + 1 < usagesList.size()) {
        b.append(" | ");
      }
    }
    da.add(new String[] { "CertType", b.toString() });
  }

  private static void getAuthnContextDisp(AuthnContext authCont, List<String[]> da) {
    List<SAMLAuthContext> statementInfoList = authCont.getStatementInfoList();
    for (int stIdx = 0; stIdx < statementInfoList.size(); stIdx++) {
      da.add(new String[] { "SAMLAuthContext" + getIndexStr(stIdx), "http://id.elegnamnden.se/auth-cont/1.0/saci" });
      SAMLAuthContext samlAuthContext = statementInfoList.get(stIdx);
      try {
        AuthContextInfo aci = samlAuthContext.getAuthContextInfo();
        addDispItem(aci.getIdentityProvider(), "  Identity Provider", da);
        addDispItem(aci.getAuthnContextClassRef(), "  Level of Assurance", da);
        addDispItem(aci.getAuthenticationInstant(), "  Authn Instant", da);
        addDispItem(aci.getAssertionRef(), "  Assertion Ref", da);
        addDispItem(aci.getServiceID(), "  ServiceID", da);

        IdAttributes idAttributes = samlAuthContext.getIdAttributes();
        if (idAttributes != null) {
          List<AttributeMapping> attributeMappingList = idAttributes.getAttributeMappings();
          for (int amIdx = 0; amIdx < attributeMappingList.size(); amIdx++) {
            AttributeMapping amt = attributeMappingList.get(amIdx);
            String ref = amt.getRef();
            String type = amt.getType().toString();
            if (type.equalsIgnoreCase("san")) {
              try {
                ref = generalNameTagText[Integer.valueOf(ref)];
              }
              catch (Exception e) {
              }
            }
            String name = amt.getAttribute().getName();
            String val = "SAML: " + name + " --> Type=" + type + " Ref=" + ref;
            addDispItem(val, "  Attribute mapping " + String.valueOf(amIdx), da);
          }
        }

      }
      catch (Exception e) {
      }
    }
  }

  private static void addDispItem(Object value, String name, List<String[]> da) {
    StringBuilder b = new StringBuilder();
    if (value != null) {
      b.append(value);
      if (b.length() > 0) {
        da.add(new String[] { name, b.toString() });
      }
    }
  }

  private static void getAltNameExtensionDisp(GeneralNames san, List<String[]> da) {
    GeneralName[] names = san.getNames();
    if (names != null) {
      for (GeneralName name : names) {
        String toString = name.toString();
        try {
          int tagNo = Integer.valueOf(toString.substring(0, toString.indexOf(":")));
          da.add(new String[] { generalNameTagText[tagNo], toString.substring(toString.indexOf(":") + 1) });

        }
        catch (Exception e) {
        }
      }
    }
  }

  private static void getPolicyMappingsText(PolicyMappings instance, List<String[]> da) {

    final ASN1Sequence pmSeq = (ASN1Sequence) instance.toASN1Primitive();
    final Iterator<ASN1Encodable> iterator = pmSeq.iterator();
    while (iterator.hasNext()){
      ASN1Sequence oidSeq = ASN1Sequence.getInstance(iterator.next());
      String idp = ASN1ObjectIdentifier.getInstance(oidSeq.getObjectAt(0)).getId();
      String sdp = ASN1ObjectIdentifier.getInstance(oidSeq.getObjectAt(0)).getId();
      da.add(new String[]{"Mapping", "issuer: " + idp + " --> subject: " + sdp});
    }
  }

  private static void getPolicyConstraintsText(PolicyConstraints instance, List<String[]> da) {

    final BigInteger requireExplicitPolicyMapping = instance.getRequireExplicitPolicyMapping();
    if (requireExplicitPolicyMapping != null){
      da.add(new String[]{"Require explicit", requireExplicitPolicyMapping.toString()});
    }
    final BigInteger inhibitPolicyMapping = instance.getInhibitPolicyMapping();
    if (inhibitPolicyMapping != null) {
      da.add(new String[]{"Inhibit mapping", inhibitPolicyMapping.toString()});
    }
  }

  private static void getNameConstraintsText(NameConstraints instance, List<String[]> da) {

    final GeneralSubtree[] permittedSubtrees = instance.getPermittedSubtrees();
    final GeneralSubtree[] excludedSubtrees = instance.getExcludedSubtrees();

    printGeneralSubtree("Permitted Subtree", permittedSubtrees, da);
    printGeneralSubtree("Excluded Subtree", excludedSubtrees, da);
  }

  private static void printGeneralSubtree(String title, GeneralSubtree[] generalSubtreeArray, List<String[]> da) {
    if (generalSubtreeArray != null && generalSubtreeArray.length > 0 ){
      for (int i = 0; i< generalSubtreeArray.length ; i++){
        GeneralSubtree subtree = generalSubtreeArray[i];
        da.add(new String[]{title + "["+i+"]", getGeneralNameStr(subtree.getBase())});
        if (subtree.getMinimum() != null){
          da.add(new String[]{"  minimum", subtree.getMinimum().toString()});
        }
        if (subtree.getMaximum() != null){
          da.add(new String[]{"  maximum", subtree.getMaximum().toString()});
        }
      }
    }
  }

  private static void getInhibitAnyPolicyText(InhibitAnyPolicy instance, List<String[]> da) {
    da.add(new String[]{"Skip certs", instance.getSkipCerts().toString()});
  }



  private static String getHtmlDisplay(List<UnitDisplayData> dispList, String heading, CertTableClasses tableClasses) {
    StringBuilder htmlStr = new StringBuilder();

    TableElement certTable = new TableElement();
    certTable.addAttribute("class", tableClasses.getTableClasses());

    if (heading != null) {
      TableElement headTable = new TableElement();
      headTable.addAttribute("class", tableClasses.getHeadTableClasses());
      headTable.addRow(heading, tableClasses.getHeadClasses(), 2, true);
      htmlStr.append(headTable);
    }

    for (UnitDisplayData dispData : dispList) {
      List<String[]> dataArray = dispData.getDataArray();

      UnitType type = dispData.getType();
      switch (type) {
      case certFields:
        for (String[] strArray : dataArray) {
          if (strArray != null && strArray.length > 1) {
            strArray[1] = strArray[1].replaceAll("\n", "<br>");
          }
          certTable.addRow(strArray, tableClasses.getCertFieldClasses());
        }
        break;
      case extension:
        StringBuilder b = new StringBuilder();
        b.append("Extension ").append(dispData.getSequence() + 1).append(":   ");
        b.append(dispData.getName()).append(" (").append(dispData.getId()).append(") - ");
        b.append(dispData.isCriticality() ? "critical   " : "not critical   ");
        certTable.addRow(b.toString(), tableClasses.getExtensionHeadClasses(), 2, true);
        if (dispData.isStructured()) {
          for (String[] strArray : dataArray) {
            String param = strArray[0];
            if (param.startsWith(" ")) {
              certTable.addRow(padParam(strArray), tableClasses.getCertExtensionSubDataClasses());
            }
            else {
              certTable.addRow(strArray, tableClasses.getCertExtensionDataClasses());
            }
          }
        }
        else {
          certTable.addRow(new String[] { "ExtensionData", dispData.getFreeText().replaceAll("\n", "<br>").trim() },
            tableClasses.getCertExtensionDataClasses());
        }
        break;
      case signature:
        certTable.addRow("Certificate Signature", tableClasses.getExtensionHeadClasses(), 2, true);
        if (dispData.isStructured()) {
          for (String[] strArray : dataArray) {
            certTable.addRow(strArray, tableClasses.getSignatureDataClassesNorm());
          }
        }
        else {
          try {
            certTable.addRow(new String[] { "Signature value", dispData.getFreeText().trim().replaceAll("\n", "<br>") },
              tableClasses.getSignatureDataClassesVerbose());
          }
          catch (Exception ex) {
            certTable.addRow(new String[] { "Signature value", "Unable to parse signature value: " + ex.getMessage() });
            Logger.getLogger(DisplayCert.class.getName()).warning("Problem parsing signature value - " + ex.getMessage());
          }
        }
        break;
      default:
        throw new AssertionError(type.name());

      }

    }
    htmlStr.append(certTable);
    return htmlStr.toString();

  }

  private static void getQcStatementsDisp(QCStatements qcstatements, List<String[]> da) {
    int idx = 0;
    if (qcstatements.isPkixSyntaxV1()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "QC Syntax V1" });
    }
    if (qcstatements.isPkixSyntaxV2()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "QC Syntax V2" });
    }
    if (qcstatements.isPkixSyntaxV1() || qcstatements.isPkixSyntaxV2()) {
      SemanticsInformation semanticsInfo = qcstatements.getSemanticsInfo();
      if (semanticsInfo != null) {
        if (semanticsInfo.getSemanticsIdentifier() != null) {
          da.add(new String[] { "  SemanticsID", OidName.getName(semanticsInfo.getSemanticsIdentifier().getId()) });
        }
        if (!semanticsInfo.getNameRegistrationAuthorityList().isEmpty()) {
          semanticsInfo.getNameRegistrationAuthorityList().forEach((name) -> {
            da.add(new String[] { "  NameRegAuth", getGeneralNameStr(name) });
          });
        }
      }
    }

    if (qcstatements.isQcCompliance()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "Qualified Certificate" });
    }
    if (qcstatements.isQcSscd()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "QC SSCD" });
    }
    if (qcstatements.isQcType()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "QC Type" });
      for (ASN1ObjectIdentifier type : qcstatements.getQcTypeIdList()) {
        if (type.getId().equalsIgnoreCase(QCStatements.QC_TYPE_ELECTRONIC_SIGNATURE.getId())) {
          da.add(new String[] { "  Type", "Electronic Signature" });
        }
        if (type.getId().equalsIgnoreCase(QCStatements.QC_TYPE_ELECTRONIC_SEAL.getId())) {
          da.add(new String[] { "  Type", "Electronic Seal" });
        }
        if (type.getId().equalsIgnoreCase(QCStatements.QC_TYPE_WEBSITE_AUTH.getId())) {
          da.add(new String[] { "  Type", "Website Authentication" });
        }
      }
    }
    if (qcstatements.isLimitValue()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "Reliance Limit" });
      MonetaryValue monetaryValue = qcstatements.getMonetaryValue();
      da.add(new String[] { "  Currency", monetaryValue.getCurrency() });
      da.add(new String[] { "  Amount", monetaryValue.getAmount().toString() });
      da.add(new String[] { "  Exponent", monetaryValue.getExponent().toString() });
    }
    if (qcstatements.isRetentionPeriod()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "Retention Period" });
      da.add(new String[] { "  Years", qcstatements.getRetentionPeriodVal().toString() });
    }
    if (qcstatements.isPdsStatement()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "PKI Disclosure Statements" });
      for (PDSLocation pdsLoc : qcstatements.getLocationList()) {
        da.add(new String[] { "  Location", "Lang=" + pdsLoc.getLang() + " URL: " + pdsLoc.getUrl() });
      }
    }
    if (qcstatements.isQcCClegislation()) {
      da.add(new String[] { "Statement" + getIndexStr(idx++), "QC Legislation Countries" });
      for (String country : qcstatements.getLegislationCountryList()) {
        da.add(new String[] { "  Country", country });
      }
    }
  }

  private static String[] padParam(String[] strArray) {
    if (strArray == null || strArray.length < 1) {
      return strArray;
    }
    strArray[0] = "&nbsp;&nbsp;" + strArray[0];
    //        if (strArray[0].trim().startsWith("-")) {
    //            strArray[0] = "&nbsp;&nbsp;&nbsp;-&nbsp;" + strArray[0];
    //        } else {
    //            strArray[0] = "&nbsp;&nbsp;" + strArray[0];
    //        }

    return strArray;
  }

  private static String getIndexStr(int i) {
    return "[" + String.valueOf(i) + "]";
  }

  private static String getCertNameFieldPrint(X500Name name, boolean decode, boolean html) {
    List<SubjectAttributeInfo> attrInfoList = new ArrayList<>();
    try {
      if (!decode) {
        return name.toString();
      }
      ASN1InputStream ain = new ASN1InputStream(name.getEncoded());
      ASN1Sequence nameSeq = ASN1Sequence.getInstance(ain.readObject());

      Map<SubjectDnType, String> subjectDnAttributeMap = new EnumMap<SubjectDnType, String>(SubjectDnType.class);
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

    }
    catch (Exception e) {
      return "Name parsing Error";
    }

    if (html) {
      TableElement dnTable = new TableElement();
      dnTable.addAttribute("class", DEF_TABLE_CLASSES.getSubjectDNTableClasses());
      for (SubjectAttributeInfo attrInfo : attrInfoList) {
        dnTable.addRow(new String[] { attrInfo.getDispName(), attrInfo.getValue() }, DEF_TABLE_CLASSES.getSubjectDNRowClasses());
      }
      return dnTable.toString();
    }
    else {
      StringBuilder b = new StringBuilder();
      for (int i = 0; i<attrInfoList.size(); i++) {
        SubjectAttributeInfo attrInfo = attrInfoList.get(i);
        if (i == 0) {
          b.append("\n");
        }
        b.append("        ").append(attrInfo.getDispName()).append(": ").append(attrInfo.getValue()).append("\n");
      }
      return b.toString();
    }
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
    if (rdnVal instanceof DERIA5String) {
      DERIA5String str = (DERIA5String) rdnVal;
      return str.getString();
    }
    if (rdnVal instanceof ASN1GeneralizedTime) {
      ASN1GeneralizedTime dgTime = (ASN1GeneralizedTime) rdnVal;
      try {
        return Instant.ofEpochMilli(dgTime.getDate().getTime()).atZone(ZoneId.of("UTC")).format(DateTimeFormatter.ISO_LOCAL_DATE);
      }
      catch (Exception e) {
        dgTime.toString();
      }
    }
    return rdnVal.toString();
  }

}
