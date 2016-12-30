package com.shark.PKIUtil.cert;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;

import java.util.Map;

/**
 *  Certificate ::= SEQUENCE {
    tbsCertificate          TBSCertificate,
    signatureAlgorithm      AlgorithmIdentifier,
    signature               BIT STRING
    }

  TBSCertificate ::= SEQUENCE {
     version          [ 0 ]  Version DEFAULT v1(0),
     serialNumber            CertificateSerialNumber,
     signature               AlgorithmIdentifier,
     issuer                  Name,
     validity                Validity,
     subject                 Name,
     subjectPublicKeyInfo    SubjectPublicKeyInfo,
     issuerUniqueID    [ 1 ] IMPLICIT UniqueIdentifier OPTIONAL,
     subjectUniqueID   [ 2 ] IMPLICIT UniqueIdentifier OPTIONAL,
     extensions        [ 3 ] Extensions OPTIONAL
     }
    详细的证书格式内容可参考：https://tools.ietf.org/html/rfc5280
 */
public class ParseX509Cert {

    /**
     * @param certContent DER编码格式的证书内容
     */
    public void parseX509Cert(byte[] certContent) throws Exception{
        /**
         * 方式一，先构造 ASN1结构，再构造 X509结构
         *  ASN1Sequence seq = (ASN1Sequence)ASN1Primitive.fromByteArray(certContent);
         *   Certificate cert = Certificate.getInstance(seq);
         */
        //方式二，直接从byte数组构造X509证书结构
        Certificate cert = Certificate.getInstance(certContent);

        /**
         * 获取证书的主题项
         */
        Map<String ,String> subjectDN = SubjectUtil.getSubjectMap(cert.getSubject());
        System.out.println(subjectDN.get(SubjectUtil.C_OID));
        System.out.println(subjectDN.get(SubjectUtil.CN_OID));
        System.out.println(subjectDN.get(SubjectUtil.E_OID));
        System.out.println(subjectDN.get(SubjectUtil.L_OID));
        System.out.println(subjectDN.get(SubjectUtil.S_OID));

        /**
         * 获取颁发者主题项，
         */
        Map<String ,String> issuerDN = SubjectUtil.getSubjectMap(cert.getIssuer());
        System.out.println(issuerDN.get(SubjectUtil.C_OID));
        System.out.println(issuerDN.get(SubjectUtil.CN_OID));
        System.out.println(issuerDN.get(SubjectUtil.E_OID));
        System.out.println(issuerDN.get(SubjectUtil.L_OID));
        System.out.println(issuerDN.get(SubjectUtil.S_OID));

        /**
         * 获取证书有效期
         */
        System.out.println("有效期开始时间" + cert.getStartDate().getDate());
        System.out.println("有效期结束时间" + cert.getEndDate().getDate());

        /**
         * 获取证书序列号
         * 一般从证书中看到的证书序列号的位数都是双数的（十六进制），如果不足的话，需要在签名补0
         */
        String certSN = cert.getSerialNumber().getPositiveValue().toString(16);
        if(certSN.length() % 2 != 0){
            certSN = "0" + certSN;
        }
        System.out.println("证书序列号为 " + certSN);

        /**
         * 获取证书扩展
         */
        Extensions extensions = cert.getTBSCertificate().getExtensions();
        ASN1ObjectIdentifier[] asn1ObjectIdentifiers = extensions.getExtensionOIDs();
        for(ASN1ObjectIdentifier asn1ObjectIdentifier:asn1ObjectIdentifiers){
            Extension extension = extensions.getExtension(asn1ObjectIdentifier);
            System.out.println("扩展的OID是" + extension.getExtnId());
            System.out.println("是否为关键扩展" + extension.isCritical());
            /**
             * 注意： 证书扩展的 呈现出来的 字符串类型，但是内部可能也是 ASN.1编码的。
             *        如果需要对 扩展值做进一步的 处理，可以采用 extension.getParsedValue();
             *        此时返回的是 ASN1Encodable结构，可以根据 定义的扩展的结构做进一步的处理
             */

            System.out.print("扩展的值为 " + extension.getExtnValue());
        }

        //TODO 考虑如何对证书进行验证,参考别人的代码
        this.verifyCert(certContent);
    }

    /**
     * 初步考虑验证以下一些内容:
     *   1.证书有效期
     *   2.证书链是否受信任
     *   3.证书用途（用于签名/加密/密钥协商）
     *   4.验证证书吊销状态（CRL或是OCSP）
     * @param certContent
     */
    private void verifyCert(byte[] certContent) {

    }
}
