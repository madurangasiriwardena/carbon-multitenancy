/*
 * Copyright (c) (2005-2026), WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.keystore.mgt;

import org.apache.axiom.om.util.UUIDGenerator;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.wso2.carbon.CarbonException;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.RegistryResources;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.core.util.TenantPKCS11KeyStore;
import org.wso2.carbon.keystore.mgt.util.RealmServiceHolder;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.ServerConstants;
import org.wso2.carbon.utils.security.KeystoreUtils;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;

/**
 * This class is used to generate a key store for a tenant and store it in the governance registry.
 * This class also provides APIs for idp-mgt component to generate a trust store with a given name.
 */
public class KeyStoreGenerator {

    private static Log log = LogFactory.getLog(KeyStoreGenerator.class);
    private int tenantId;
    private String tenantDomain;
    private String password;
    private static final String SIGNING_ALG = "Tenant.SigningAlgorithm";

    // Supported signature algorithms for public certificate generation.
    private static final String RSA_MD5 = "MD5withRSA";
    private static final String RSA_SHA1 = "SHA1withRSA";
    private static final String RSA_SHA256 = "SHA256withRSA";
    private static final String RSA_SHA384 = "SHA384withRSA";
    private static final String RSA_SHA512 = "SHA512withRSA";
    private static final String[] signatureAlgorithms = new String[]{
            RSA_MD5, RSA_SHA1, RSA_SHA256, RSA_SHA384, RSA_SHA512
    };

    // Tenant key stores held in a PKCS#11 token (HSM): [keystore.tenant] type = "PKCS11".
    private static final String PKCS11_STORE_TYPE = "PKCS11";
    private static final String PKCS11_KEYSTORE_EXTENSION = ".p11";



    public KeyStoreGenerator(int  tenantId) throws KeyStoreMgtException {

        this.tenantId = tenantId;
        this.tenantDomain = getTenantDomainName();
    }


    /**
     * This method first generates the keystore, then persist it in the gov.registry of that tenant.
     * The key algorithm and key size come from {@code [keystore.tenant] key_algorithm} and
     * {@code [keystore.tenant] key_size}. They apply only to keystores generated after they are set.
     *
     * @throws KeyStoreMgtException Error when generating or storing the keystore, or when the configured key
     *                              algorithm or key size is invalid
     */
    public void generateKeyStore() throws KeyStoreMgtException {

        // Resolve the key configuration first, so that an invalid value fails before any keystore is created.
        String keyAlgorithm;
        int keySize;
        try {
            keyAlgorithm = KeystoreUtils.getTenantKeyAlgorithm();
            keySize = KeystoreUtils.getTenantKeySize();
        } catch (CarbonException e) {
            throw new KeyStoreMgtException(e.getMessage(), e);
        }
        if (PKCS11_STORE_TYPE.equals(KeystoreUtils.StoreFileType.defaultFileType())) {
            generatePKCS11KeyStore(keyAlgorithm, keySize);
            return;
        }
        try {
            password = generatePassword();
            KeyStore keyStore = KeystoreUtils.getKeystoreInstance(KeystoreUtils.StoreFileType.defaultFileType());
            keyStore.load(null, password.toCharArray());
            X509Certificate pubCert = generateKeyPair(keyStore, keyAlgorithm, keySize);
            persistKeyStore(keyStore, pubCert);
        } catch (Exception e) {
            String msg = "Error while instantiating a keystore";
            log.error(msg, e);
            throw new KeyStoreMgtException(msg, e);
        }
    }

    /**
     * This method first generates the keystore, then persist it in the gov.registry of that tenant
     *
     * @throws KeyStoreMgtException Error when generating or storing the keystore
     */
    public void generateTrustStore(String trustStoreName) throws KeyStoreMgtException {
        try {
            password = generatePassword();
            KeyStore keyStore = KeystoreUtils.getKeystoreInstance(KeystoreUtils.getTrustStoreFileType());
            keyStore.load(null, password.toCharArray());
            persistTrustStore(keyStore, trustStoreName);
        } catch (Exception e) {
            String msg = "Error while instantiating a keystore";
            log.error(msg, e);
            throw new KeyStoreMgtException(msg, e);
        }
    }
    
    /**
     * This method checks the existance of a keystore
     *
     * @param tenantId
     * @return
     * @throws KeyStoreMgtException
     */
    public boolean isKeyStoreExists(int tenantId) throws KeyStoreMgtException{

        String keyStoreName = generateKSNameFromDomainName();
        try {
            KeyStoreAdmin keystoreAdmin = new KeyStoreAdmin(tenantId);
            KeyStore keyStore = keystoreAdmin.getKeyStore(keyStoreName);
            if (keyStore != null) {
                return true;
            }
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error while checking the existence of keystore.", e);
            }
        }
        return false;
    }

    /**
     * This method generates the keypair and stores it in the keystore
     *
     * @param keyStore A keystore instance
     * @param keyAlgorithm Key algorithm of the key pair
     * @param keySize Key size of the key pair in bits
     * @return Generated public key for the tenant
     * @throws KeyStoreMgtException Error when generating key pair
     */
    private X509Certificate generateKeyPair(KeyStore keyStore, String keyAlgorithm, int keySize)
            throws KeyStoreMgtException {
        try {
            CryptoUtil.getDefaultCryptoUtil();
            //generate key pair
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm);
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            String algorithmName = getSignatureAlgorithm();
            JcaContentSignerBuilder signerBuilder =
                    new JcaContentSignerBuilder(algorithmName).setProvider(getJCEProvider());
            X509Certificate x509Cert = createSelfSignedCertificate(keyPair, signerBuilder);

            //add private key to KS
            keyStore.setKeyEntry(tenantDomain, keyPair.getPrivate(), password.toCharArray(),
                    new java.security.cert.Certificate[]{x509Cert});
            return x509Cert;
        } catch (Exception ex) {
            String msg = "Error while generating the certificate for tenant :" +
                         tenantDomain + ".";
            log.error(msg, ex);
            throw new KeyStoreMgtException(msg, ex);
        }

    }

    /**
     * Delete the tenant's PKCS11 key store, if the tenant has one. Deleting it also removes the tenant key pair from
     * the token. Tenants with file based key stores are not changed.
     *
     * @throws KeyStoreMgtException Error when deleting the key store.
     */
    public void deletePKCS11KeyStore() throws KeyStoreMgtException {

        String keyStoreName = tenantDomain.trim().replace(".", "-") + PKCS11_KEYSTORE_EXTENSION;
        KeyStoreAdmin keyStoreAdmin = new KeyStoreAdmin(tenantId);
        KeyStore keyStore;
        try {
            keyStore = keyStoreAdmin.getKeyStore(keyStoreName);
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Tenant: " + tenantDomain + " has no PKCS11 key store.", e);
            }
            return;
        }
        if (keyStore == null || !PKCS11_STORE_TYPE.equals(keyStore.getType())) {
            return;
        }
        try {
            keyStoreAdmin.deleteStore(keyStoreName);
        } catch (Exception e) {
            String msg = "Error while deleting the PKCS11 key store of tenant: " + tenantDomain;
            log.error(msg, e);
            throw new KeyStoreMgtException(msg, e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Deleted the PKCS11 key store of tenant: " + tenantDomain);
        }
    }

    /**
     * Create the self-signed certificate of the tenant key pair.
     *
     * @param keyPair       Tenant key pair.
     * @param signerBuilder Signer for the certificate, bound to the provider that can use the private key.
     * @return Self-signed certificate.
     * @throws Exception Error when building or signing the certificate.
     */
    private X509Certificate createSelfSignedCertificate(KeyPair keyPair, JcaContentSignerBuilder signerBuilder)
            throws Exception {

        // Common Name and alias for the generated certificate
        String commonName = "CN=" + tenantDomain + ", OU=None, O=None, L=None";

        //generate certificates
        X500Name distinguishedName = new X500Name(commonName);

        Date notBefore = new Date(System.currentTimeMillis() - 1000L * 60 * 60 * 24 * 30);
        Date notAfter = new Date(System.currentTimeMillis() + (1000L * 60 * 60 * 24 * 365 * 10));

        SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(keyPair.getPublic().getEncoded());
        BigInteger serialNumber = new BigInteger(32, new SecureRandom());

        X509v3CertificateBuilder certificateBuilder = new X509v3CertificateBuilder(
                distinguishedName,
                serialNumber,
                notBefore,
                notAfter,
                distinguishedName,
                subPubKeyInfo
        );
        PrivateKey privateKey = keyPair.getPrivate();
        return new JcaX509CertificateConverter().setProvider(getJCEProvider())
                .getCertificate(certificateBuilder.build(signerBuilder.build(privateKey)));
    }

    /**
     * Generate the tenant key pair in the PKCS#11 token configured by {@code [keystore.tenant] provider} and
     * register a PKCS11 tenant key store that refers to it. The key pair is generated in the token and the
     * self-signed certificate is signed in the token, so the private key never exists outside the token.
     *
     * @param keyAlgorithm Key algorithm of the key pair.
     * @param keySize      Key size of the key pair in bits.
     * @throws KeyStoreMgtException Error when the token is not configured, or generating or storing the key fails.
     */
    private void generatePKCS11KeyStore(String keyAlgorithm, int keySize) throws KeyStoreMgtException {

        ServerConfiguration config = ServerConfiguration.getInstance();
        String providerName = StringUtils.trim(config.getFirstProperty(
                RegistryResources.SecurityManagement.TENANT_KEYSTORE_PROVIDER));
        String pin = config.getFirstProperty(RegistryResources.SecurityManagement.TENANT_KEYSTORE_PASSWORD);
        if (StringUtils.isBlank(providerName) || StringUtils.isEmpty(pin)) {
            throw new KeyStoreMgtException("[keystore.tenant] provider and password are required when the tenant " +
                    "key store type is " + PKCS11_STORE_TYPE + ".");
        }
        Provider provider = Security.getProvider(providerName);
        if (provider == null) {
            throw new KeyStoreMgtException("The JCA provider '" + providerName + "' of the tenant key store token " +
                    "is not registered.");
        }

        // The kernel derives the label from the tenant ID and accepts only that label for this tenant.
        String label = TenantPKCS11KeyStore.labelFor(tenantId);
        KeyStore token;
        try {
            token = KeyStore.getInstance(PKCS11_STORE_TYPE, provider);
            token.load(null, pin.toCharArray());
            if (token.containsAlias(label)) {
                throw new KeyStoreMgtException("The tenant key store token already has an entry with label: " +
                        label);
            }
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(keyAlgorithm, provider);
            keyPairGenerator.initialize(keySize);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            JcaContentSignerBuilder signerBuilder =
                    new JcaContentSignerBuilder(getSignatureAlgorithm()).setProvider(provider);
            X509Certificate certificate = createSelfSignedCertificate(keyPair, signerBuilder);
            token.setKeyEntry(label, keyPair.getPrivate(), null, new Certificate[]{certificate});
        } catch (KeyStoreMgtException e) {
            throw e;
        } catch (Exception e) {
            String msg = "Error while generating the key pair of tenant: " + tenantDomain + " in the token of " +
                    "provider: " + providerName;
            log.error(msg, e);
            throw new KeyStoreMgtException(msg, e);
        }
        if (log.isDebugEnabled()) {
            log.debug("Generated the key pair of tenant: " + tenantDomain + " in the token of provider: " +
                    providerName + " with label: " + label);
        }

        try {
            // The key store record names the token entry. The token's provider and PIN stay in the configuration.
            KeyStoreManager.getInstance(tenantId).addTenantPKCS11KeyStore();
        } catch (Exception e) {
            // Do not leave an unreferenced key pair in the token.
            try {
                token.deleteEntry(label);
            } catch (Exception deleteError) {
                log.error("Error while removing the token entry: " + label + " after a failed key store " +
                        "registration.", deleteError);
            }
            String msg = "Error when registering the PKCS11 key store of tenant: " + tenantDomain;
            log.error(msg, e);
            throw new KeyStoreMgtException(msg, e);
        }
    }

    /**
     * Persist the keystore in the gov.registry
     *
     * @param keyStore created Keystore of the tenant
     * @param PKCertificate pub. key of the tenant
     * @throws KeyStoreMgtException Exception when storing the keystore in the registry
     */
    private void persistKeyStore(KeyStore keyStore, X509Certificate PKCertificate)
            throws KeyStoreMgtException {

        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            keyStore.store(outputStream, password.toCharArray());
            outputStream.flush();
            outputStream.close();

            String keyStoreName = generateKSNameFromDomainName();
            // Use the keystore using the keystore admin
            KeyStoreAdmin keystoreAdmin = new KeyStoreAdmin(tenantId);
            keystoreAdmin.addKeyStore(outputStream.toByteArray(), keyStoreName,
                                      password, " ", KeystoreUtils.StoreFileType.defaultFileType(), password);
        } catch (Exception e) {
            String msg = "Error when processing keystore/pub. cert to be stored in registry";
            log.error(msg, e);
            throw new KeyStoreMgtException(msg, e);
        }
    }

    /**
     * Persist the trust store in the gov.registry
     *
     * @param trustStore created trust store of the tenant
     * @throws KeyStoreMgtException Exception when storing the trust store in the registry
     */
    private void persistTrustStore(KeyStore trustStore, String trustStoreName) throws KeyStoreMgtException {
        try {
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            trustStore.store(outputStream, password.toCharArray());
            outputStream.flush();
            outputStream.close();

            KeyStoreAdmin keystoreAdmin = new KeyStoreAdmin(tenantId);
            keystoreAdmin.addTrustStore(outputStream.toByteArray(), trustStoreName, password, " ",
                    KeystoreUtils.getTrustStoreFileType());
        } catch (Exception e) {
            String msg = "Error when processing keystore/pub. cert to be stored in registry";
            log.error(msg, e);
            throw new KeyStoreMgtException(msg, e);
        }
    }

    /**
     * This method is used to generate a random password for the generated keystore
     *
     * @return generated password
     */
    private String generatePassword() {
        SecureRandom random = new SecureRandom();
        String randString = new BigInteger(130, random).toString(12);
        return randString.substring(randString.length() - 10, randString.length());
    }

    /**
     * This method is used to generate a file name appender for the pub. cert, e.g.
     * example-com-343743.cert
     * @return generated string to be used as a file name appender
     */
    private String generatePubKeyFileNameAppender(){
        String uuid = UUIDGenerator.getUUID();
        return uuid.substring(uuid.length() - 6, uuid.length()-1);
    }

    /**
     * This method generates the key store file name from the Domain Name
     * @return
     */
    private String generateKSNameFromDomainName(){
        String ksName = tenantDomain.trim().replace(".", "-");
        return (ksName + KeystoreUtils.getExtensionByFileType(KeystoreUtils.StoreFileType.defaultFileType()));
    }

    private String getTenantDomainName() throws KeyStoreMgtException {
        RealmService realmService = RealmServiceHolder.getRealmService();
        if (realmService == null) {
            String msg = "Error in getting the domain name, realm service is null.";
            log.error(msg);
            throw new KeyStoreMgtException(msg);
        }
        try {
            return realmService.getTenantManager().getDomain(tenantId);
        } catch (org.wso2.carbon.user.api.UserStoreException e) {
            String msg = "Error in getting the domain name for the tenant id: " + tenantId;
            log.error(msg, e);
            throw new KeyStoreMgtException(msg, e);
        }
    }

    private static String getJCEProvider() {

        String provider = ServerConfiguration.getInstance().getFirstProperty(ServerConstants.JCE_PROVIDER);
        if (!StringUtils.isBlank(provider)) {
            return provider;
        }
        return ServerConstants.JCE_PROVIDER_BC;
    }

    private static String getSignatureAlgorithm() {

        String algorithm = ServerConfiguration.getInstance().getFirstProperty(SIGNING_ALG);
        // Find in a list of supported signature algorithms.
        for (String supportedAlgorithm : signatureAlgorithms) {
            if (supportedAlgorithm.equalsIgnoreCase(algorithm)) {
                return supportedAlgorithm;
            }
        }
        return RSA_MD5;
    }
}
