/*
 * Copyright (C) 2021 The Android Open Source Project
 *           (C) 2023 ArrowOS
 *           (C) 2023 The LibreMobileOS Foundation
 *           (C) 2024 The LeafOS Project
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

package com.android.internal.gmscompat;

import android.app.ActivityTaskManager;
import android.app.Application;
import android.app.TaskStackListener;
import android.content.ComponentName;
import android.content.Context;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Build;
import android.os.Environment;
import android.os.Process;
import android.os.SystemProperties;
import android.security.keystore.KeyProperties;
import android.system.keystore2.KeyEntryResponse;
import android.text.TextUtils;
import android.util.Log;

import org.json.JSONException;
import org.json.JSONObject;
import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Field;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.ThreadLocalRandom;

import org.spongycastle.asn1.ASN1Boolean;
import org.spongycastle.asn1.ASN1Encodable;
import org.spongycastle.asn1.ASN1EncodableVector;
import org.spongycastle.asn1.ASN1Enumerated;
import org.spongycastle.asn1.ASN1ObjectIdentifier;
import org.spongycastle.asn1.ASN1OctetString;
import org.spongycastle.asn1.ASN1Sequence;
import org.spongycastle.asn1.ASN1TaggedObject;
import org.spongycastle.asn1.DEROctetString;
import org.spongycastle.asn1.DERSequence;
import org.spongycastle.asn1.DERTaggedObject;
import org.spongycastle.asn1.pkcs.PrivateKeyInfo;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.cert.X509CertificateHolder;
import org.spongycastle.cert.X509v3CertificateBuilder;
import org.spongycastle.openssl.PEMKeyPair;
import org.spongycastle.openssl.PEMParser;
import org.spongycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;

/** @hide */
public final class AttestationHooks {
    private static final String TAG = AttestationHooks.class.getSimpleName();
    private static final boolean DEBUG = Log.isLoggable(TAG, Log.DEBUG);

    private static final String PACKAGE_GMS = "com.google.android.gms";
    private static final String PROCESS_UNSTABLE = "com.google.android.gms.unstable";
    private static final String SAMSUNG = "com.samsung.android.";
    private static final String DATA_FILE = "gms_certified_props.json";
    private static final String KEYBOX_DATA_FILE = "gms_keybox.xml";

    private static final boolean SPOOF_GMS =
            SystemProperties.getBoolean("persist.sys.spoof.gms", true);

    private static final ComponentName GMS_ADD_ACCOUNT_ACTIVITY =
            ComponentName.unflattenFromString(
                    "com.google.android.gms/.auth.uiflows.minutemaid.MinuteMaidActivity");

    private static volatile String sProcessName;
    private static volatile boolean sIsGms = false;

    private static final String ATTR_ALGORITHM = "algorithm";
    private static final String TAG_KEY = "Key";
    private static final String TAG_PRIVATE_KEY = "PrivateKey";
    private static final String TAG_CERTIFICATE = "Certificate";

    private static String savedKeybox;
    private static PrivateKey EC, RSA;
    private static byte[] EC_CERTS;
    private static byte[] RSA_CERTS;
    private static final ASN1ObjectIdentifier OID = new ASN1ObjectIdentifier("1.3.6.1.4.1.11129.2.1.17");
    private static CertificateFactory certificateFactory;
    private static X509CertificateHolder EC_holder, RSA_holder;
    private static volatile String algo;

    private AttestationHooks() {}

    private static void setBuildField(String key, String value) {
        try {
            // Unlock
            Class clazz = Build.class;
            if (key.startsWith("VERSION:")) {
                clazz = Build.VERSION.class;
                key = key.substring(8);
            }
            Field field = clazz.getDeclaredField(key);
            field.setAccessible(true);

            // Edit
            if (field.getType().equals(Long.TYPE)) {
                field.set(null, Long.parseLong(value));
            } else if (field.getType().equals(Integer.TYPE)) {
                field.set(null, Integer.parseInt(value));
            } else {
                field.set(null, value);
            }

            // Lock
            field.setAccessible(false);
        } catch (Exception e) {
            Log.e(TAG, "Failed to spoof Build." + key, e);
        }
    }

    public static void initApplicationBeforeOnCreate(Context context) {
        final String packageName = context.getPackageName();
        final String processName = Application.getProcessName();

        if (TextUtils.isEmpty(packageName) || TextUtils.isEmpty(processName)) {
            Log.e(TAG, "Null package or process name");
            return;
        }

        if (SPOOF_GMS && PACKAGE_GMS.equals(packageName)) {
            setBuildField("TIME", String.valueOf(System.currentTimeMillis()));
            if (PROCESS_UNSTABLE.equals(processName)) {
                sProcessName = processName;
                sIsGms = true;
                setGmsCertifiedProps();
            }
        }

        // Samsung apps like SmartThings, Galaxy Wearable crashes
        // on samsung devices running AOSP
        if (packageName.startsWith(SAMSUNG)) {
            setBuildField("BRAND", "google");
            setBuildField("MANUFACTURER", "google");
        }
    }

    private static void setGmsCertifiedProps() {
        File dataFile = new File(Environment.getDataSystemDirectory(), DATA_FILE);
        String savedProps = readFromFile(dataFile);

        if (TextUtils.isEmpty(savedProps)) {
            Log.e(TAG, "No props found to spoof");
            return;
        }

        dlog("Found props");
        final boolean was = isGmsAddAccountActivityOnTop();
        final TaskStackListener taskStackListener =
                new TaskStackListener() {
                    @Override
                    public void onTaskStackChanged() {
                        final boolean is = isGmsAddAccountActivityOnTop();
                        if (is ^ was) {
                            // process will restart automatically later
                            dlog(
                                    "GmsAddAccountActivityOnTop is:"
                                            + is
                                            + " was:"
                                            + was
                                            + ", killing myself!");
                            Process.killProcess(Process.myPid());
                        }
                    }
                };
        if (!was) {
            try {
                JSONObject parsedProps = new JSONObject(savedProps);
                Iterator<String> keys = parsedProps.keys();

                while (keys.hasNext()) {
                    String key = keys.next();
                    String value = parsedProps.getString(key);
                    dlog(key + ": " + value);

                    setBuildField(key, value);
                }
            } catch (JSONException e) {
                Log.e(TAG, "Error parsing JSON data", e);
            }
        } else {
            dlog("Skip spoofing build for GMS, because GmsAddAccountActivityOnTop");
        }
        try {
            ActivityTaskManager.getService().registerTaskStackListener(taskStackListener);
        } catch (Exception e) {
            Log.e(TAG, "Failed to register task stack listener!", e);
        }
    }

    private static boolean isGmsAddAccountActivityOnTop() {
        try {
            final ActivityTaskManager.RootTaskInfo focusedTask =
                    ActivityTaskManager.getService().getFocusedRootTaskInfo();
            return focusedTask != null
                    && focusedTask.topActivity != null
                    && focusedTask.topActivity.equals(GMS_ADD_ACCOUNT_ACTIVITY);
        } catch (Exception e) {
            Log.e(TAG, "Unable to get top activity!", e);
        }
        return false;
    }

    public static boolean shouldBypassTaskPermission(Context context) {
        // GMS doesn't have MANAGE_ACTIVITY_TASKS permission
        final int callingUid = Binder.getCallingUid();
        final int gmsUid;
        try {
            gmsUid = context.getPackageManager().getApplicationInfo(PACKAGE_GMS, 0).uid;
            dlog("shouldBypassTaskPermission: gmsUid:" + gmsUid + " callingUid:" + callingUid);
        } catch (Exception e) {
            return false;
        }
        return gmsUid == callingUid;
    }

    public static boolean hasSystemFeature(String name, boolean ret) {
        if (PackageManager.FEATURE_KEYSTORE_APP_ATTEST_KEY.equals(name)
            || PackageManager.FEATURE_STRONGBOX_KEYSTORE.equals(name)) {
            return false;
        }
        return ret;
    }

    private static String convertPEMToBase64(String str) {
        return str.replaceAll("-----[^-]*-----", "").replaceAll("\n", "");
    }

    private static String formatPEM(String str) {
        return str.replaceAll("(-----[^-]*-----)", "\n$1\n");
    }

    private static PrivateKey parsePrivateKey(String str) throws Throwable {
        PEMParser parser = new PEMParser(new StringReader(formatPEM(str)));
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter();

        try {
            Object result = parser.readObject();
            PrivateKeyInfo keyInfo = null;
            if (result instanceof PEMKeyPair) {
                PEMKeyPair keyPair = (PEMKeyPair) result;
                keyInfo = PrivateKeyInfo.getInstance(keyPair.getPrivateKeyInfo());
            } else if (result instanceof PrivateKeyInfo) {
                keyInfo = PrivateKeyInfo.getInstance((PrivateKeyInfo) result);
            }
            return converter.getPrivateKey(keyInfo);
        } catch (Throwable t) {
            Log.e(TAG, "Failed to parse private key", t);
        }

        return null;
    }

    private static byte[] parseCert(String str) {
        return Base64.getDecoder().decode(convertPEMToBase64(str));
    }

    private static byte[] getCertificateChain(String algo) throws Throwable {
        if (KeyProperties.KEY_ALGORITHM_EC.equals(algo)) {
            return EC_CERTS;
        } else if (KeyProperties.KEY_ALGORITHM_RSA.equals(algo)) {
            return RSA_CERTS;
        }
        throw new Exception();
    }

    private static boolean parseKeybox() {
        File dataFile = new File(Environment.getDataSystemDirectory(), KEYBOX_DATA_FILE);
        String keybox = readFromFile(dataFile);

        if (TextUtils.isEmpty(keybox)) {
            Log.e(TAG, "No keybox found to spoof");
            return false;
        }

        if (savedKeybox != null && savedKeybox.equals(keybox)) {
            dlog("Keybox already loaded");
            return true;
        }

        dlog("Found keybox");
        try {
            certificateFactory = CertificateFactory.getInstance("X.509");
            ByteArrayOutputStream stream = new ByteArrayOutputStream();

            XmlPullParserFactory factory = XmlPullParserFactory.newInstance();
            XmlPullParser xpp = factory.newPullParser();

            String algorithm = "";
            String privateKey = "";
            List<String> certificateChain = new ArrayList<>();

            xpp.setInput(new StringReader(keybox));
            int eventType = xpp.getEventType();
            String currentTag = null;
            while (eventType != XmlPullParser.END_DOCUMENT) {
                if (eventType == XmlPullParser.START_TAG) {
                    if (TAG_KEY.equalsIgnoreCase(xpp.getName())) {
                        algorithm = xpp.getAttributeValue(null, ATTR_ALGORITHM);
                        privateKey = "";
                        certificateChain = new ArrayList<>();
                    }

                    currentTag = xpp.getName();
                } else if (eventType == XmlPullParser.END_TAG) {
                    if (TAG_KEY.equalsIgnoreCase(xpp.getName())) {
                        stream.reset();

                        switch (algorithm.toUpperCase(Locale.ROOT)) {
                            case "ECDSA":
                                EC = parsePrivateKey(privateKey);
                                if (EC == null) return false;

                                for (int i = 0; i < certificateChain.size(); i++) {
                                    byte[] cert = parseCert(certificateChain.get(i));

                                    stream.write(cert);
                                    if (i == 0) {
                                        EC_holder = new X509CertificateHolder(cert);
                                    }
                                }

                                EC_CERTS = stream.toByteArray();

                                break;
                            case "RSA":
                                RSA = parsePrivateKey(privateKey);
                                if (RSA == null) return false;

                                for (int i = 0; i < certificateChain.size(); i++) {
                                    byte[] cert = parseCert(certificateChain.get(i));

                                    stream.write(cert);
                                    if (i == 0) {
                                        RSA_holder = new X509CertificateHolder(cert);
                                    }
                                }

                                RSA_CERTS = stream.toByteArray();
                                break;
                            default:
                                Log.e(TAG, "Unknown algorithm: " + algorithm);
                                break;
                        }
                    }

                    currentTag = null;
                } else if (eventType == XmlPullParser.TEXT) {
                    if (TAG_PRIVATE_KEY.equalsIgnoreCase(currentTag)) {
                        privateKey = xpp.getText();
                    } else if (TAG_CERTIFICATE.equalsIgnoreCase(currentTag)) {
                        certificateChain.add(xpp.getText());
                    }
                }

                eventType = xpp.next();
            }

            stream.close();

            savedKeybox = keybox;
            return true;
        } catch (Throwable t) {
            Log.e(TAG, "Error parsing keybox XML", t);
        }

        return false;
    }

    private static byte[] modifyLeaf(byte[] bytes) throws Throwable {
        X509Certificate leaf = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(bytes));

        if (leaf.getExtensionValue(OID.getId()) == null) throw new Exception();

        X509CertificateHolder holder = new X509CertificateHolder(leaf.getEncoded());

        Extension ext = holder.getExtension(OID);

        ASN1Sequence sequence = ASN1Sequence.getInstance(ext.getExtnValue().getOctets());

        ASN1Encodable[] encodables = sequence.toArray();

        ASN1Sequence teeEnforced = (ASN1Sequence) encodables[7];

        ASN1EncodableVector vector = new ASN1EncodableVector();

        ASN1Sequence rootOfTrust = null;
        for (ASN1Encodable asn1Encodable : teeEnforced) {
            ASN1TaggedObject taggedObject = (ASN1TaggedObject) asn1Encodable;
            if (taggedObject.getTagNo() == 704) {
                rootOfTrust = (ASN1Sequence) taggedObject.getObject();
                continue;
            }
            vector.add(asn1Encodable);
        }

        if (rootOfTrust == null) throw new Exception();

        algo = leaf.getPublicKey().getAlgorithm();

        boolean isEC = KeyProperties.KEY_ALGORITHM_EC.equals(algo);

        X509CertificateHolder cert1 = isEC ? EC_holder : RSA_holder;
        PrivateKey privateKey = isEC ? EC : RSA;

        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(cert1.getSubject(), holder.getSerialNumber(), holder.getNotBefore(), holder.getNotAfter(), holder.getSubject(), holder.getSubjectPublicKeyInfo());
        ContentSigner signer = new JcaContentSignerBuilder(leaf.getSigAlgName()).build(privateKey);

        byte[] verifiedBootKey = new byte[32];
        ThreadLocalRandom.current().nextBytes(verifiedBootKey);

        DEROctetString verifiedBootHash = (DEROctetString) rootOfTrust.getObjectAt(3);

        if (verifiedBootHash == null) {
            byte[] temp = new byte[32];
            ThreadLocalRandom.current().nextBytes(temp);
            verifiedBootHash = new DEROctetString(temp);
        }

        ASN1Encodable[] rootOfTrustEnc = {new DEROctetString(verifiedBootKey), ASN1Boolean.TRUE, new ASN1Enumerated(0), new DEROctetString(verifiedBootHash)};

        ASN1Sequence rootOfTrustSeq = new DERSequence(rootOfTrustEnc);

        ASN1TaggedObject rootOfTrustTagObj = new DERTaggedObject(704, rootOfTrustSeq);

        vector.add(rootOfTrustTagObj);

        ASN1Sequence hackEnforced = new DERSequence(vector);

        encodables[7] = hackEnforced;

        ASN1Sequence hackedSeq = new DERSequence(encodables);

        ASN1OctetString hackedSeqOctets = new DEROctetString(hackedSeq);

        Extension hackedExt = new Extension(OID, false, hackedSeqOctets);

        builder.addExtension(hackedExt);

        for (ASN1ObjectIdentifier extensionOID : holder.getExtensions().getExtensionOIDs()) {
            if (OID.getId().equals(extensionOID.getId())) continue;
            builder.addExtension(holder.getExtension(extensionOID));
        }

        return builder.build(signer).getEncoded();
    }

    public static KeyEntryResponse onGetKeyEntry(KeyEntryResponse response) {
        if (response == null) return null;

        if (response.metadata == null) return response;

        if (!parseKeybox()) return response;

        algo = null;

        try {
            byte[] newLeaf = modifyLeaf(response.metadata.certificate);
            response.metadata.certificateChain = getCertificateChain(algo);

            response.metadata.certificate = newLeaf;

        } catch (Throwable t) {
            if (DEBUG) Log.e(TAG, "onGetKeyEntry", t);
        }

        return response;
    }

    private static String readFromFile(File file) {
        StringBuilder content = new StringBuilder();

        if (file.exists()) {
            try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
                String line;

                while ((line = reader.readLine()) != null) {
                    content.append(line);
                }
            } catch (IOException e) {
                Log.e(TAG, "Error reading from file", e);
            }
        }
        return content.toString();
    }

    private static void dlog(String message) {
        if (DEBUG) Log.d(TAG, "[" + sProcessName + "] " + message);
    }
}
