package com.android.internal.util;
/*
 * Copyright (C) 2025 Vulcanzier
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


import android.media.audio.common.Int;
import android.os.FileUtils;
import android.util.Log;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.io.File;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

//Imitation of KeyProviderManager.java class.
public class KeyBoxData {
    private static final String TAG = "Luph-KeyBoxData";
    private static final boolean DEBUG = true;

    public static class CertItem {
        public String privateKey;
        public String[] certificates;

        public CertItem(String privateKey, String[] certificates) {
            this.privateKey = privateKey;
            this.certificates = certificates; }
    }

    public CertItem EC;
    public CertItem RSA;

    public KeyBoxData(CertItem EC, CertItem RSA) {
        this.EC = EC;
        this.RSA = RSA;
    }

    //Use AOSP to pass Device integrity by default
    private static KeyBoxData getAospKeyBoxData() {
        return new KeyBoxData(
                new KeyBoxData.CertItem(
                        "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEICHghkMqFRmEWc82OlD8FMnarfk19SfC39ceTW28QuVEoAoGCCqGSM49AwEHoUQDQgAE6555+EJjWazLKpFMiYbMcK2QZpOCqXMmE/6sy/ghJ0whdJdKKv6luU1/ZtTgZRBmNbxTt6CjpnFYPts+Ea4QFA==\n-----END EC PRIVATE KEY-----",
                        new String[]{
                                "-----BEGIN CERTIFICATE-----\nMIICeDCCAh6gAwIBAgICEAEwCgYIKoZIzj0EAwIwgZgxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxMzAxBgNVBAMMKkFuZHJvaWQgS2V5c3RvcmUgU29mdHdhcmUgQXR0ZXN0YXRpb24gUm9vdDAeFw0xNjAxMTEwMDQ2MDlaFw0yNjAxMDgwMDQ2MDlaMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTswOQYDVQQDDDJBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOueefhCY1msyyqRTImGzHCtkGaTgqlzJhP+rMv4ISdMIXSXSir+pblNf2bU4GUQZjW8U7ego6ZxWD7bPhGuEBSjZjBkMB0GA1UdDgQWBBQ//KzWGrE6noEguNUlHMVlux6RqTAfBgNVHSMEGDAWgBTIrel3TEXDo88NFhDkeUM6IVowzzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIChDAKBggqhkjOPQQDAgNIADBFAiBLipt77oK8wDOHri/AiZi03cONqycqRZ9pDMfDktQPjgIhAO7aAV229DLp1IQ7YkyUBO86fMy9Xvsiu+f+uXc/WT/7\n-----END CERTIFICATE-----",
                                "-----BEGIN CERTIFICATE-----\nMIICizCCAjKgAwIBAgIJAKIFntEOQ1tXMAoGCCqGSM49BAMCMIGYMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMTMwMQYDVQQDDCpBbmRyb2lkIEtleXN0b3JlIFNvZnR3YXJlIEF0dGVzdGF0aW9uIFJvb3QwHhcNMTYwMTExMDA0MzUwWhcNMzYwMTA2MDA0MzUwWjCBmDELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDEzMDEGA1UEAwwqQW5kcm9pZCBLZXlzdG9yZSBTb2Z0d2FyZSBBdHRlc3RhdGlvbiBSb290MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7l1ex+HA220Dpn7mthvsTWpdamguD/9/SQ59dx9EIm29sa/6FsvHrcV30lacqrewLVQBXT5DKyqO107sSHVBpKNjMGEwHQYDVR0OBBYEFMit6XdMRcOjzw0WEOR5QzohWjDPMB8GA1UdIwQYMBaAFMit6XdMRcOjzw0WEOR5QzohWjDPMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgKEMAoGCCqGSM49BAMCA0cAMEQCIDUho++LNEYenNVg8x1YiSBq3KNlQfYNns6KGYxmSGB7AiBNC/NR2TB8fVvaNTQdqEcbY6WFZTytTySn502vQX3xvw==\n-----END CERTIFICATE-----"
                        }
                ),
                new KeyBoxData.CertItem(
                        "-----BEGIN RSA PRIVATE KEY-----\nMIICXQIBAAKBgQDAgyPcVogbuDAgafWwhWHG7r5/BeL1qEIEir6LR752/q7yXPKbKvoyABQWAUKZiaFfz8aBXrNjWDwv0vIL5Jgyg92BSxbX4YVBeuVKvClqOm21wAQIO2jFVsHwIzmRZBmGTVC3TUCuykhMdzVsiVoMJ1q/rEmdXX0jYvKcXgLocQIDAQABAoGBAL6GCwuZqAKm+xpZQ4p7txUGWwmjbcbpysxr88AsNNfXnpTGYGQo2Ix7f2V3wc3qZAdKvo5yht8fCBHclygmCGjeldMu/Ja20IT/JxpfYN78xwPno45uKbqaPF/CwoB2tqiWrx0014gozpvdsfNPnJQEQweBKY4gExZyW728mTpBAkEA4cbZJ2RsCRbsNoJtWUmDdAwh8bB0xKGlmGfGaXlchdPcRkxbkp6Uv7NODcxQFLEPEzQat/3V9gQU0qMmytQcxQJBANpIWZd4XNVjD7D9jFJU+Y5TjhiYOq6ea35qWntdNDdVuSGOvUAyDSg4fXifdvohi8wti2il9kGPu+ylF5qzr70CQFD+/DJklVlhbtZTThVFCTKdk6PYENvlvbmCKSz3i9i624Agro1X9LcdBThv/p6dsnHKNHejSZnbdvjl7OnA1J0CQBW3TPJ8zv+Ls2vwTZ2DRrCaL3DS9EObDyasfgP36dH3fUuRX9KbKCPwOstdUgDghX/yqAPpPu6W1iNc6VRCvCECQQCQp0XaiXCyzWSWYDJCKMX4KFb/1mW6moXI1g8bi+5xfs0scurgHa2GunZU1M9FrbXx8rMdn4Eiz6XxpVcPmy0l\n-----END RSA PRIVATE KEY-----",
                        new String[]{
                                "-----BEGIN CERTIFICATE-----\nMIICtjCCAh+gAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwYzELMAkGA1UEBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDU1vdW50YWluIFZpZXcxFTATBgNVBAoMDEdvb2dsZSwgSW5jLjEQMA4GA1UECwwHQW5kcm9pZDAeFw0xNjAxMDQxMjQwNTNaFw0zNTEyMzAxMjQwNTNaMHYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQxKTAnBgNVBAMMIEFuZHJvaWQgU29mdHdhcmUgQXR0ZXN0YXRpb24gS2V5MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAgyPcVogbuDAgafWwhWHG7r5/BeL1qEIEir6LR752/q7yXPKbKvoyABQWAUKZiaFfz8aBXrNjWDwv0vIL5Jgyg92BSxbX4YVBeuVKvClqOm21wAQIO2jFVsHwIzmRZBmGTVC3TUCuykhMdzVsiVoMJ1q/rEmdXX0jYvKcXgLocQIDAQABo2YwZDAdBgNVHQ4EFgQU1AwQG/jNY7n3OVK1DhNcpteZk4YwHwYDVR0jBBgwFoAUKfrxrMxN0kyWQCd1trDpMuUH/i4wEgYDVR0TAQH/BAgwBgEB/wIBADAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADgYEAni1IX4xnM9waha2Z11Aj6hTsQ7DhnerCI0YecrUZ3GAi5KVoMWwLVcTmnKItnzpPk2sxixZ4Fg2Iy9mLzICdhPDCJ+NrOPH90ecXcjFZNX2W88V/q52PlmEmT7K+gbsNSQQiis6f9/VCLiVE+iEHElqDtVWtGIL4QBSbnCBjBH8=\n-----END CERTIFICATE-----",
                                "-----BEGIN CERTIFICATE-----\nMIICpzCCAhCgAwIBAgIJAP+U2d2fB8gMMA0GCSqGSIb3DQEBCwUAMGMxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRYwFAYDVQQHDA1Nb3VudGFpbiBWaWV3MRUwEwYDVQQKDAxHb29nbGUsIEluYy4xEDAOBgNVBAsMB0FuZHJvaWQwHhcNMTYwMTA0MTIzMTA4WhcNMzUxMjMwMTIzMTA4WjBjMQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNTW91bnRhaW4gVmlldzEVMBMGA1UECgwMR29vZ2xlLCBJbmMuMRAwDgYDVQQLDAdBbmRyb2lkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCia63rbi5EYe/VDoLmt5TRdSMfd5tjkWP/96r/C3JHTsAsQ+wzfNes7UA+jCigZtX3hwszl94OuE4TQKuvpSe/lWmgMdsGUmX4RFlXYfC78hdLt0GAZMAoDo9Sd47b0ke2RekZyOmLw9vCkT/X11DEHTVm+Vfkl5YLCazOkjWFmwIDAQABo2MwYTAdBgNVHQ4EFgQUKfrxrMxN0kyWQCd1trDpMuUH/i4wHwYDVR0jBBgwFoAUKfrxrMxN0kyWQCd1trDpMuUH/i4wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAoQwDQYJKoZIhvcNAQELBQADgYEAT3LzNlmNDsG5dFsxWfbwjSVJMJ6jHBwp0kUtILlNX2S06IDHeHqcOd6os/W/L3BfRxBcxebrTQaZYdKumgf/93y4q+ucDyQHXrF/unlx/U1bnt8Uqf7f7XzAiF343ZtkMlbVNZriE/mPzsF83O+kqrJVw4OpLvtc9mL1J1IXvmM=\n-----END CERTIFICATE-----"
                        }
                )
        );
    }

    private static String readFileContent(File file) {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        } catch (IOException e) {
            Log.e(TAG, "Error reading file content", e);
        }
        return content.toString();
    }

    private static KeyBoxData getUserKeyBox() {
        try{
            String KEYBOX_PATH = "/data/system/keybox.xml";
            File keyBoxFile = new File(KEYBOX_PATH);
            if (keyBoxFile.exists()) {
                String keyboxStringEnc;
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
                    keyboxStringEnc = FileUtils.readTextFile(new File(KEYBOX_PATH), 0, null);
                } else {
                    keyboxStringEnc = readFileContent(new File(KEYBOX_PATH));
                }

                String password = KeyBoxPassword.PASSWORD;
                byte[] key = generateKey(password);
                SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
                Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] iv = new byte[cipher.getBlockSize()];
                System.arraycopy(KeyBoxPassword.fixedIv, 0, iv, 0, iv.length);
                IvParameterSpec ivParams = new IvParameterSpec(iv);
                cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);
                byte[] keyboxBytes = Base64.getDecoder().decode(keyboxStringEnc);
                byte[] keyboxDecrypted = cipher.doFinal(keyboxBytes);
                String keyboxString = new String(keyboxDecrypted, StandardCharsets.UTF_8);

                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                DocumentBuilder builder = factory.newDocumentBuilder();
                Document document = builder.parse(new InputSource(new StringReader(keyboxString)));

                NodeList privateKeyNodes = document.getElementsByTagName("PrivateKey");
                String EC_PRIVATE_KEY = privateKeyNodes.item(0).getTextContent();
                String RSA_PRIVATE_KEY = privateKeyNodes.item(1).getTextContent();


                NodeList certificateNodes = document.getElementsByTagName("Certificate");
                int numbCertsPerEnc = certificateNodes.getLength()/2;
                String[] EC_CERTIFICATES = new String[numbCertsPerEnc];
                String[] RSA_CERTIFICATES = new String[numbCertsPerEnc];
                for (int i = 0; i < numbCertsPerEnc; i++) {
                    EC_CERTIFICATES[i] = certificateNodes.item(i).getTextContent();
                    RSA_CERTIFICATES[i] = certificateNodes.item(i + numbCertsPerEnc).getTextContent();
                }

                return new KeyBoxData(
                        new KeyBoxData.CertItem(EC_PRIVATE_KEY, EC_CERTIFICATES),
                        new KeyBoxData.CertItem(RSA_PRIVATE_KEY, RSA_CERTIFICATES)
                );
            } else {
                return null;
            }
        } catch (Exception e) {
            Log.e(TAG, "Error reading keybox", e);
            return null;
        }

    }

    public static KeyBoxData getKeyBoxData() {
        KeyBoxData userKeyBoxData = getUserKeyBox();
        return userKeyBoxData != null ? userKeyBoxData : getAospKeyBoxData();
    }

    private static byte[] generateKey(String password) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        return sha.digest(password.getBytes(StandardCharsets.UTF_8));
    }

    private static void dlog(String msg) {
        if (DEBUG) {
            android.util.Log.d(TAG, msg);
        }
    }

}
