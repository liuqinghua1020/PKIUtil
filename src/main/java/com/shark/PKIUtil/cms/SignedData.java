package com.shark.PKIUtil.cms;

import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by liuqinghua on 2016-12-30.
 * 主要使用BC的 CMSSignedDataGenerator 处理
 */
public class SignedData {
    public void signCMSSignedData(X509Certificate signCert, KeyPair signKP) throws Exception{
        List certList = new ArrayList();
        CMSTypedData msg = new CMSProcessableByteArray("Hello world!".getBytes());

        certList.add(signCert);

        Store certs = new JcaCertStore(certList);

        CMSSignedDataGenerator gen = new CMSSignedDataGenerator();
        ContentSigner sha1Signer = new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(signKP.getPrivate());

        gen.addSignerInfoGenerator(
                new JcaSignerInfoGeneratorBuilder(
                        new JcaDigestCalculatorProviderBuilder().setProvider("BC").build())
                        .build(sha1Signer, signCert));

        gen.addCertificates(certs);

        CMSSignedData sigData = gen.generate(msg, false);
    }

    public void verifyCMSSignedData(){

    }
}
