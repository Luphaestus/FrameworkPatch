package com.android.internal.util;

public class KeyBoxData {
    public static class CertItem {
        public String privateKey;
        public String[] certificates;

        private String removerCertHeaders(String cert) {
            return cert.split("\n")[1];
        }

        public CertItem(String privateKey, String[] certificates) {
            boolean removeHeaders = false;
            this.privateKey = removeHeaders? removerCertHeaders(privateKey): privateKey;
            this.certificates = removeHeaders? java.util.Arrays.stream(certificates).map(this::removerCertHeaders).toArray(String[]::new): certificates; }
    }

    public CertItem EC;
    public CertItem RSA;

    public KeyBoxData(CertItem EC, CertItem RSA) {
        this.EC = EC;
        this.RSA = RSA;
    }
}