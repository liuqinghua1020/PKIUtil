package com.shark.PKIUtil.cert;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.SignedData;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

/**
 * Created by liuqinghua on 2017-04-06.
 * 本类主要研究下 对于终端证书，如何使用其颁发者的公钥对其证书签名做验证
 *
 * 相关的处理说明可以查看地址:
 */
public class verifyCertPathSignature {

    public static void main(String[] args) {
        try{
            verifyCertPathSignature();
        }catch(Exception e){
            e.printStackTrace();
        }
    }

    private static void verifyCertPathSignature() throws Exception{
        String certfn= "C:\\Users\\liuqinghua\\Desktop\\安全中心问题\\证书链\\CA.p7b";
        FileInputStream fi= new FileInputStream(certfn);
        byte[] p7b= new byte[fi.available()];
        fi.read(p7b);
        fi.close();
        certfn= "C:\\Users\\liuqinghua\\Desktop\\安全中心问题\\GDCA\\cert_der.cer";
        fi= new FileInputStream(certfn);
        byte[] cer= new byte[fi.available()];
        fi.read(cer);
        fi.close();
        X509Certificate certobj= ParseToCertObj(cer);
        boolean ret= VerifyCertWithP7B(certobj,p7b);
        System.out.println(ret);
    }

    private static boolean VerifyCertWithP7B(X509Certificate certobj,byte[] p7b) {
        try{
            ContentInfo cntinfo= ContentInfo.getInstance(p7b);
            SignedData p7bobj= SignedData.getInstance(cntinfo.getContent());
            ASN1Set set= p7bobj.getCertificates();
            for(int i=0; i<set.size(); i++){
                ASN1Sequence seq= (ASN1Sequence) set.getObjectAt(i);
                X509Certificate cacertobj= ParseToCertObj(seq.getEncoded(ASN1Encoding.DER));
                if(!certobj.getIssuerX500Principal().equals(cacertobj.getSubjectX500Principal()))
                    continue;

                //下面的代码是核心,这是一个 查看 P1 签名值的一个比较核心的代码
                byte[] signature= certobj.getSignature();
                BigInteger bsi= new BigInteger(signature);
                RSAPublicKey capubkey= (RSAPublicKey) cacertobj.getPublicKey();
                BigInteger tmp= bsi.modPow(capubkey.getPublicExponent(), capubkey.getModulus());
                String strtmp= tmp.toString(16);
                System.out.println("P1签名的原文摘要值+填充数据为 \r\n " + strtmp);
                certobj.verify(cacertobj.getPublicKey());

                return true;
            }
            return false;
        }catch(Exception e){
            e.printStackTrace();
            return false;
        }
    }

    private static X509Certificate ParseToCertObj(byte[] certBytes) throws CertificateException {
        // 实例化证书工厂
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        // 取得证书文件流
        InputStream inputStream = new ByteArrayInputStream(certBytes);
        // 生成证书
        Certificate certificate = factory.generateCertificate(inputStream);
        return (X509Certificate) certificate;
    }
}
