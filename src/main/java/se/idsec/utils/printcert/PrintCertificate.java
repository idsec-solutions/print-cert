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
package se.idsec.utils.printcert;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;

import se.idsec.utils.printcert.display.CertTableClasses;
import se.idsec.utils.printcert.display.DisplayCert;
import se.idsec.utils.printcert.extension.ExtensionInfo;
import se.idsec.utils.printcert.utils.CertUtils;
import se.idsec.utils.printcert.utils.PEM;

/**
 * This extension of the Bouncy castle X509CertificateHolder adds extended printing capabilities for
 * outputting the certificate content to text or html
 *
 * @author Stefan Santeson
 */
public class PrintCertificate extends X509CertificateHolder {
    
    private static final long serialVersionUID = 3088571489307085589L;
    
    Map<String, ExtensionInfo> extensionsMap;
    List<ExtensionInfo> extensionInfoList;
    X509Certificate cert;
    String certStringRepr;

    /**
     * Constructor
     * @param cert {@link X509Certificate}
     * @throws CertificateEncodingException exception parsing certificate
     * @throws CertificateException exception parsing certificate
     * @throws IOException exception parsing certificate
     */
    public PrintCertificate(X509Certificate cert) throws CertificateEncodingException, CertificateException, IOException {
        super(cert.getEncoded());
        initValues();
    }

    /**
     * Constructor
     * @param bytes certificate bytes
     * @throws CertificateException exception parsing certificate
     * @throws IOException exception parsing certificate
     */
    public PrintCertificate(byte[] bytes) throws CertificateException, IOException {
        super(bytes);
        initValues();
    }

    /**
     * Constructor
     * @param x509CertificateHolder {@link X509CertificateHolder}
     * @throws IOException exception parsing certificate
     */
    public PrintCertificate(X509CertificateHolder x509CertificateHolder) throws IOException {
        super(x509CertificateHolder.getEncoded());
        initValues();
    }

    private final void initValues() {
        certStringRepr = toOriginalString();
        this.extensionsMap = new HashMap<>();
        try {
            this.cert = toX509Certificate();
            extensionInfoList = CertUtils.getExtensions(this);
            if (extensionInfoList != null && !extensionInfoList.isEmpty()) {
                for (ExtensionInfo ext : extensionInfoList) {
                    extensionsMap.put(ext.getOid().getId(), ext);
                }
            }

        } catch (IOException | CertificateException | NoSuchProviderException ex) {
            //Logger.getLogger(AaaCertificate.class.getName()).log(Level.SEVERE, null, ex);
            Logger.getLogger(PrintCertificate.class.getName()).warning("Certificate parsing error: " + ex.getMessage());
            throw new IllegalArgumentException("Illegal certificate content: " + ex.getMessage());
        }
    }

    public ExtensionInfo getExtensionInfo(String oid) {
        if (extensionsMap.containsKey(oid)) {
            return extensionsMap.get(oid);
        }
        return null;
    }

    /**
     * Extension info Map. Oid string as key
     *
     * @return
     */
    public Map<String, ExtensionInfo> getExtensionsMap() {
        return extensionsMap;
    }

    public List<ExtensionInfo> getExtensionInfoList() {
        return extensionInfoList;
    }

    public X509Certificate getCert() {
        return cert;
    }

    public PublicKey getPublicKey() {
        return cert.getPublicKey();
    }
    
    public int getBasicConstraints() {
        return cert.getBasicConstraints();
    }
    
    public X500Principal getIssuerX500Principal(){
        return cert.getIssuerX500Principal();
    }

    public X500Principal getSubjectX500Principal(){
        return cert.getSubjectX500Principal();
    }
    
    public byte[] getExtensionValue(String oid){
        return cert.getExtensionValue(oid);
    }
    
    @Override
    public Date getNotAfter(){
        return cert.getNotAfter();
    }
    @Override
    public Date getNotBefore(){
        return cert.getNotBefore();
    }
    
    @Override
    public byte[] getEncoded(){
        try {
            return super.getEncoded();
        } catch (IOException ex) {
            Logger.getLogger(PrintCertificate.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    @Override
    public BigInteger getSerialNumber(){
        return cert.getSerialNumber();
    }
    
    public byte[] getSubjectKeyInfo() {
        ExtensionInfo extension = getExtensionInfo(Extension.subjectKeyIdentifier.getId());
        if (extension == null) {
            return null;
        }
        SubjectKeyIdentifier skiData = SubjectKeyIdentifier.getInstance(extension.getExtDataASN1());
        return skiData.getKeyIdentifier();
    }

    @Override
    public String toString() {
        try {
            return DisplayCert.certToDisplayString(this, true, false, false);
        } catch (Exception ex){
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
            return toOriginalString();
        }
    }

    /**
     * Generates a printout of the current certificate
     *
     * @param verbose set to true to print out explicit key parameter and
     * signature values
     * @return Print string
     */
    public String toString(boolean verbose) {
        try {
            return DisplayCert.certToDisplayString(this, true, verbose, false);
        } catch (Exception ex){
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
            return toOriginalString();
        }
    }

    /**
     * Generates a printout of the current certificate
     *
     * @param verbose set to true to print out explicit key parameter and
     * signature values
     * @return Print string
     */
    public String toString(boolean monospace, boolean verbose) {
        try {
            return DisplayCert.certToDisplayString(this, monospace, verbose, false);
        } catch (Exception ex){
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
            return toOriginalString();
        }
    }

    /**
     * Generates a printout of the current certificate
     *
     * @param monospace indicates that the print is done using monospace characters
     * @param verbose set to true to print out explicit key parameter and
     * @param decode set to true to decode name parameters
     * signature values
     * @return Print string
     */
    public String toString(boolean monospace, boolean verbose, boolean decode) {
        try {
            return DisplayCert.certToDisplayString(this, monospace, verbose, decode);
        } catch (Exception ex){
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
            return toOriginalString();
        }
    }



    /**
     * Provides the original certificate print format provided by the
     * X509Certificate class
     *
     * @return Print string
     */
    public String toOriginalString() {
        try {
            return toX509Certificate().toString();
        } catch (IOException | CertificateException |NoSuchProviderException ex) {
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
        }
        return super.toString();
    }

    /**
     * Generates HTML print of the current certificate
     *
     * @param heading A heading to add to the print. Null if none.
     * @param tableClasses The html classes to be added to print table elements
     * @param verbose Set to true to display explicit values of key parameters
     * and signature value
     * @param decodeSubject set to true to decode subject and issuer attributes
     * for friendly display. False for the traditional one line X500 name print.
     * @return html print
     */
    public String toHtml(String heading, CertTableClasses tableClasses, boolean verbose, boolean decodeSubject) {
        try {
            return DisplayCert.certToHtmlString(this, heading, tableClasses, true, decodeSubject);
        } catch (Exception ex){
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
            return "<pre><code>"+ toOriginalString() + "</code></pre>";
        }
    }

    /**
     * Generates HTML print of the current certificate using default table
     * classes.
     *
     * @param heading A heading to add to the print. Null if none.
     * @param verbose Set to true to display explicit values of key parameters
     * and signature value
     * @param decodeSubject
     * @return html print
     */
    public String toHtml(String heading, boolean verbose, boolean decodeSubject) {
        try {
            return DisplayCert.certToHtmlString(this, heading, verbose, decodeSubject);
        } catch (Exception ex){
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
            return "<pre><code>"+ toOriginalString() + "</code></pre>";
        }
    }

    /**
     * Generates HTML print of the current certificate using default table
     * classes.
     *
     * @param verbose Set to true to display explicit values of key parameters
     * and signature value
     * @return html print
     */
    public String toHtml(boolean verbose) {
        try {
            return DisplayCert.certToHtmlString(this, null, verbose);
        } catch (Exception ex){
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
            return "<pre><code>"+ toOriginalString() + "</code></pre>";
        }
    }

    /**
     * Generates HTML print of the current certificate using default table
     * classes.
     *
     * @return html print
     */
    public String toHtml() {
        try {
            return DisplayCert.certToHtmlString(this, null, false);
        } catch (Exception ex){
            Logger.getLogger(PrintCertificate.class.getName()).warning("Failed to print certificate info: "+ ex.getMessage());
            return "<pre><code>"+ toOriginalString() + "</code></pre>";
        }
    }

    public String toPEM() {
        return PEM.getPemCert(this.getEncoded());
    }

    private X509Certificate toX509Certificate() throws IOException, CertificateException, NoSuchProviderException {
        try (InputStream inStream = new ByteArrayInputStream(this.getEncoded())) {
            CertificateFactory cf = CertificateFactory.getInstance("X.509", "BC");
            X509Certificate certificate = (X509Certificate) cf.generateCertificate(inStream);
            return certificate;
        }
    }
}
