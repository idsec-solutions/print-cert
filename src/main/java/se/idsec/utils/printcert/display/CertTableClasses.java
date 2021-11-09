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
package se.idsec.utils.printcert.display;

/**
 *
 * @author stefan
 */
public class CertTableClasses {
    String tableClasses, headTableClasses, subjectDNTableClasses;
    String[] HeadClasses;
    String[] certFieldClasses;
    String[] extensionHeadClasses;
    String[] certExtensionDataClasses;
    String[] certExtensionSubDataClasses;
    String[] signatureDataClassesNorm;
    String[] signatureDataClassesVerbose;
    String[] subjectDNRowClasses;

    public CertTableClasses() {
    }

    public CertTableClasses(String tableClasses, String headTableClasses, String subjectDNTableClasses, String[] HeadClasses, String[] certFieldClasses, String[] extensionHeadClasses, String[] certExtensionDataClasses, String[] certExtensionSubDataClasses, String[] signatureDataClassesNorm, String[] signatureDataClassesVerbose, String[] subjectDNRowClasses) {
        this.tableClasses = tableClasses;
        this.headTableClasses = headTableClasses;
        this.subjectDNTableClasses = subjectDNTableClasses;
        this.HeadClasses = HeadClasses;
        this.certFieldClasses = certFieldClasses;
        this.extensionHeadClasses = extensionHeadClasses;
        this.certExtensionDataClasses = certExtensionDataClasses;
        this.certExtensionSubDataClasses = certExtensionSubDataClasses;
        this.signatureDataClassesNorm = signatureDataClassesNorm;
        this.signatureDataClassesVerbose = signatureDataClassesVerbose;
        this.subjectDNRowClasses = subjectDNRowClasses;
    }




    public String getTableClasses() {
        return tableClasses;
    }

    public void setTableClasses(String tableClasses) {
        this.tableClasses = tableClasses;
    }

    public String getHeadTableClasses() {
        return headTableClasses;
    }

    public void setHeadTableClasses(String headTableClasses) {
        this.headTableClasses = headTableClasses;
    }


    public String[] getCertFieldClasses() {
        return certFieldClasses;
    }

    public void setCertFieldClasses(String[] certFieldClasses) {
        this.certFieldClasses = certFieldClasses;
    }

    public String[] getCertExtensionDataClasses() {
        return certExtensionDataClasses;
    }

    public void setCertExtensionDataClasses(String[] certExtensionDataClasses) {
        this.certExtensionDataClasses = certExtensionDataClasses;
    }

    public String[] getHeadClasses() {
        return HeadClasses;
    }

    public void setHeadClasses(String[] HeadClasses) {
        this.HeadClasses = HeadClasses;
    }

    public String[] getExtensionHeadClasses() {
        return extensionHeadClasses;
    }

    public void setExtensionHeadClasses(String[] extensionHeadClasses) {
        this.extensionHeadClasses = extensionHeadClasses;
    }

    public String[] getCertExtensionSubDataClasses() {
        return certExtensionSubDataClasses;
    }

    public void setCertExtensionSubDataClasses(String[] certExtensionSubDataClasses) {
        this.certExtensionSubDataClasses = certExtensionSubDataClasses;
    }

    public String[] getSignatureDataClassesNorm() {
        return signatureDataClassesNorm;
    }

    public void setSignatureDataClassesNorm(String[] signatureDataClassesNorm) {
        this.signatureDataClassesNorm = signatureDataClassesNorm;
    }

    public String[] getSignatureDataClassesVerbose() {
        return signatureDataClassesVerbose;
    }

    public void setSignatureDataClassesVerbose(String[] signatureDataClassesVerbose) {
        this.signatureDataClassesVerbose = signatureDataClassesVerbose;
    }

    public String getSubjectDNTableClasses() {
        return subjectDNTableClasses;
    }

    public void setSubjectDNTableClasses(String subjectDNTableClasses) {
        this.subjectDNTableClasses = subjectDNTableClasses;
    }

    public String[] getSubjectDNRowClasses() {
        return subjectDNRowClasses;
    }

    public void setSubjectDNRowClasses(String[] subjectDNRowClasses) {
        this.subjectDNRowClasses = subjectDNRowClasses;
    }
    
    
}
