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


/**
 * PEM Certificate format functions.
 */
public class PEM {

    private static final String LF = System.getProperty("line.separator");
    static final String beginReq = "-----BEGIN CERTIFICATE REQUEST-----";
    static final String endReq = "-----END CERTIFICATE REQUEST-----";
    static final String beginCert = "-----BEGIN CERTIFICATE-----";
    static final String endCert = "-----END CERTIFICATE-----";

    public PEM() {
    }

    public static String getPemReq(byte[] inpData) {
        return (getPemReq(inpData, inpData.length));
    }

    public static String getPemReq(byte[] inpData, int len) {
        StringBuilder b = new StringBuilder();
        b.append(beginReq).append(LF);
        b.append(Base64Coder.encodeLines(inpData, 0, len, 76, LF));
        b.append(endReq);
        return b.toString();
    }

    public static String getPemCert(byte[] inpData) {
        return (getPemCert(inpData, inpData.length));
    }

    public static String getPemCert(byte[] inpData, String lineSeparator) {
        return (getPemCert(inpData, inpData.length,lineSeparator));
    }

    public static String getPemCert(byte[] inpData, int len) {
        return (getPemCert(inpData, len, LF));
    }

    public static String getPemCert(byte[] inpData, int len, String lineSeparator) {
        StringBuilder b = new StringBuilder();
        b.append(beginCert).append(lineSeparator);
        b.append(Base64Coder.encodeLines(inpData, 0, len, 76, lineSeparator));
        b.append(endCert);
        return b.toString();
    }

    public static String trimPemCert(String pemCert) {
        if (pemCert == null) {
            return null;
        }
        String corePemCert = pemCert;
        for (int i = 0; i < pemCert.length(); i++) {
            if (pemCert.length() - i > beginCert.length()) {
                if (pemCert.substring(i, i + beginCert.length()).equalsIgnoreCase(beginCert)) {
                    corePemCert = pemCert.substring(i, pemCert.length());
                }
            }
        }

        return (removeString(removeString(corePemCert, beginCert), endCert)).trim();
    }

    public static String removeString(String inpString, String removeString) {
        StringBuilder b = new StringBuilder();
        if (inpString.length() > removeString.length()) {
            for (int i = 0; i < inpString.length(); i++) {
                if (inpString.length() - i >= removeString.length()) {
                    if (inpString.substring(i, i + removeString.length()).equalsIgnoreCase(removeString)) {
                        i = i + removeString.length();
                    } else {
                        b.append(inpString.charAt(i));
                    }
                } else {
                    b.append(inpString.charAt(i));
                }
            }
        }

        return b.toString();
    }
}
