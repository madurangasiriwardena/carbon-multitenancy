/*
 * Copyright (c) 2026, WSO2 LLC. (http://www.wso2.com).
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

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.keystore.mgt.util.RealmServiceHolder;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.tenant.TenantManager;
import org.wso2.carbon.utils.CarbonUtils;

import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.expectThrows;

/**
 * Tests for tenant key stores generated in a PKCS#11 token: {@code [keystore.tenant] type = "PKCS11"}.
 */
public class KeyStoreGeneratorPKCS11Test {

    private static final int TENANT_ID = 7;
    private static final String TENANT_DOMAIN = "hsm.com";
    private static final String LABEL = "wso2-tenant-7";
    private static final String PROVIDER_NAME = "TestToken-is-tenants";
    private static final String PIN = "1234";

    private MockedStatic<ServerConfiguration> serverConfigurationStatic;
    private MockedStatic<CarbonUtils> carbonUtils;
    private MockedStatic<CryptoUtil> cryptoUtil;
    private MockedConstruction<KeyStoreAdmin> keyStoreAdminConstruction;
    private MockedStatic<KeyStoreManager> keyStoreManagerStatic;
    private KeyStoreManager keyStoreManager;
    private ServerConfiguration serverConfiguration;
    private TestTokenProvider tokenProvider;
    // What KeyStoreAdmin.getKeyStore returns: a KeyStore, or an Exception to throw.
    private Object existingKeyStore;

    @BeforeMethod
    public void setUp() throws Exception {

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        tokenProvider = new TestTokenProvider(PROVIDER_NAME, PIN.toCharArray());
        Security.addProvider(tokenProvider);

        serverConfiguration = mock(ServerConfiguration.class);
        when(serverConfiguration.getFirstProperty("Security.TenantKeyStore.Type")).thenReturn("PKCS11");
        when(serverConfiguration.getFirstProperty("Security.TenantKeyStore.Provider")).thenReturn(PROVIDER_NAME);
        when(serverConfiguration.getFirstProperty("Security.TenantKeyStore.Password")).thenReturn(PIN);
        when(serverConfiguration.getFirstProperty("Tenant.SigningAlgorithm")).thenReturn("SHA256withRSA");
        serverConfigurationStatic = mockStatic(ServerConfiguration.class);
        serverConfigurationStatic.when(ServerConfiguration::getInstance).thenReturn(serverConfiguration);
        carbonUtils = mockStatic(CarbonUtils.class);
        carbonUtils.when(CarbonUtils::getServerConfiguration).thenReturn(serverConfiguration);
        cryptoUtil = mockStatic(CryptoUtil.class);

        TenantManager tenantManager = mock(TenantManager.class);
        when(tenantManager.getDomain(TENANT_ID)).thenReturn(TENANT_DOMAIN);
        RealmService realmService = mock(RealmService.class);
        when(realmService.getTenantManager()).thenReturn(tenantManager);
        RealmServiceHolder.setRealmService(realmService);

        keyStoreManager = mock(KeyStoreManager.class);
        keyStoreManagerStatic = mockStatic(KeyStoreManager.class);
        keyStoreManagerStatic.when(() -> KeyStoreManager.getInstance(anyInt())).thenReturn(keyStoreManager);

        existingKeyStore = new SecurityException("Key Store does not exist.");
        keyStoreAdminConstruction = mockConstruction(KeyStoreAdmin.class, (keyStoreAdmin, context) -> {
            doAnswer(invocation -> {
                if (existingKeyStore instanceof Exception) {
                    throw (Exception) existingKeyStore;
                }
                return existingKeyStore;
            }).when(keyStoreAdmin).getKeyStore(anyString());
        });
    }

    @AfterMethod
    public void tearDown() {

        keyStoreAdminConstruction.close();
        keyStoreManagerStatic.close();
        cryptoUtil.close();
        carbonUtils.close();
        serverConfigurationStatic.close();
        RealmServiceHolder.setRealmService(null);
        Security.removeProvider(PROVIDER_NAME);
    }

    @Test
    public void testKeyPairIsGeneratedAndSignedInTheToken() throws Exception {

        new KeyStoreGenerator(TENANT_ID).generateKeyStore();

        // The key pair and certificate are stored in the token under the tenant ID based label.
        KeyStore token = KeyStore.getInstance("PKCS11", tokenProvider);
        token.load(null, PIN.toCharArray());
        assertTrue(token.isKeyEntry(LABEL));
        Key privateKey = token.getKey(LABEL, null);
        assertTrue(tokenProvider.isGeneratedKey(privateKey), "The key pair was not generated by the token.");
        X509Certificate certificate = (X509Certificate) token.getCertificate(LABEL);
        assertNotNull(certificate);
        assertTrue(certificate.getSubjectX500Principal().getName().contains("CN=" + TENANT_DOMAIN));
        assertEquals(certificate.getSigAlgName().toUpperCase(), "SHA256WITHRSA");
        assertEquals(((RSAPublicKey) certificate.getPublicKey()).getModulus().bitLength(), 2048);
        certificate.verify(certificate.getPublicKey());
        assertTrue(tokenProvider.getSignatureCount() > 0, "The certificate was not signed by the token.");

        // The kernel registers the key store record for the tenant's label. No PIN or provider is passed to it.
        verify(keyStoreManager).addTenantPKCS11KeyStore();
        keyStoreManagerStatic.verify(() -> KeyStoreManager.getInstance(TENANT_ID));
    }

    @Test
    public void testProviderAndPasswordAreRequired() throws Exception {

        when(serverConfiguration.getFirstProperty("Security.TenantKeyStore.Provider")).thenReturn(" ");
        KeyStoreMgtException e = expectThrows(KeyStoreMgtException.class,
                () -> new KeyStoreGenerator(TENANT_ID).generateKeyStore());
        assertTrue(e.getMessage().contains("provider and password are required"), e.getMessage());

        when(serverConfiguration.getFirstProperty("Security.TenantKeyStore.Provider")).thenReturn(PROVIDER_NAME);
        when(serverConfiguration.getFirstProperty("Security.TenantKeyStore.Password")).thenReturn(null);
        expectThrows(KeyStoreMgtException.class, () -> new KeyStoreGenerator(TENANT_ID).generateKeyStore());
        verify(keyStoreManager, never()).addTenantPKCS11KeyStore();
        assertFalse(tokenProvider.getToken().containsAlias(LABEL));
    }

    @Test
    public void testUnregisteredProviderFails() throws Exception {

        when(serverConfiguration.getFirstProperty("Security.TenantKeyStore.Provider")).thenReturn("NoSuchProvider");
        KeyStoreMgtException e = expectThrows(KeyStoreMgtException.class,
                () -> new KeyStoreGenerator(TENANT_ID).generateKeyStore());
        assertTrue(e.getMessage().contains("is not registered"), e.getMessage());
        verify(keyStoreManager, never()).addTenantPKCS11KeyStore();
    }

    @Test
    public void testExistingTokenEntryIsNotReplaced() throws Exception {

        new KeyStoreGenerator(TENANT_ID).generateKeyStore();
        X509Certificate existing = (X509Certificate) tokenProvider.getToken().getCertificate(LABEL);

        expectThrows(KeyStoreMgtException.class, () -> new KeyStoreGenerator(TENANT_ID).generateKeyStore());
        assertEquals(tokenProvider.getToken().getCertificate(LABEL), existing);
        // Registered only once, for the first generation.
        verify(keyStoreManager).addTenantPKCS11KeyStore();
    }

    @Test
    public void testFailedRegistrationRemovesTheTokenEntry() throws Exception {

        doThrow(new SecurityException("registration failed")).when(keyStoreManager).addTenantPKCS11KeyStore();
        expectThrows(KeyStoreMgtException.class, () -> new KeyStoreGenerator(TENANT_ID).generateKeyStore());
        assertFalse(tokenProvider.getToken().containsAlias(LABEL), "An unreferenced key pair was left in the token.");
    }

    @Test
    public void testDeletePKCS11KeyStore() throws Exception {

        KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", tokenProvider);
        pkcs11KeyStore.load(null, PIN.toCharArray());
        existingKeyStore = pkcs11KeyStore;

        new KeyStoreGenerator(TENANT_ID).deletePKCS11KeyStore();
        verify(lastKeyStoreAdmin()).deleteStore("hsm-com.p11");
    }

    @Test
    public void testDeleteLeavesFileBasedAndMissingKeyStores() throws Exception {

        KeyStore fileBased = KeyStore.getInstance("PKCS12");
        fileBased.load(null, null);
        existingKeyStore = fileBased;
        new KeyStoreGenerator(TENANT_ID).deletePKCS11KeyStore();
        verify(lastKeyStoreAdmin(), never()).deleteStore(anyString());

        existingKeyStore = new SecurityException("Key Store does not exist.");
        new KeyStoreGenerator(TENANT_ID).deletePKCS11KeyStore();
        verify(lastKeyStoreAdmin(), never()).deleteStore(anyString());
    }

    @Test
    public void testTenantDeleteListenerDeletesPKCS11KeyStore() throws Exception {

        KeyStore pkcs11KeyStore = KeyStore.getInstance("PKCS11", tokenProvider);
        pkcs11KeyStore.load(null, PIN.toCharArray());
        existingKeyStore = pkcs11KeyStore;

        new KeystoreTenantMgtListener().onPreDelete(TENANT_ID);
        verify(lastKeyStoreAdmin()).deleteStore("hsm-com.p11");
    }

    private KeyStoreAdmin lastKeyStoreAdmin() {

        java.util.List<KeyStoreAdmin> constructed = keyStoreAdminConstruction.constructed();
        return constructed.get(constructed.size() - 1);
    }
}
