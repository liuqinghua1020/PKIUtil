package com.shark.PKIUtil.cert;

import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.util.Date;

import com.shark.PKIUtil.util.Base64Util;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.TBSCertificate;
import org.bouncycastle.asn1.x509.Time;
import org.bouncycastle.asn1.x509.V3TBSCertificateGenerator;


public class MakeX509 {
	
	/**
	 *  Certificate ::= SEQUENCE {
		      tbsCertificate          TBSCertificate,
		      signatureAlgorithm      AlgorithmIdentifier,
		      signature               BIT STRING
		}
	 * @throws IOException 
	 */
	public static void makeCert() throws Exception{
		DERSequence cert = null;
		TBSCertificate tbCert = null;
		AlgorithmIdentifier ai = null;
		DERBitString signature = null;
		
		
		//创建TBSCertificate
		V3TBSCertificateGenerator  generator = new V3TBSCertificateGenerator();
		//设置开始和结束时间
		Time start = new Time(new Date());
		Time end = new Time(new Date());
		generator.setStartDate(start);
		generator.setEndDate(end);
		
		//设置证书序列号
		generator.setSerialNumber(new DERInteger(new java.math.BigInteger("123")));
		
		//颁发者
		X500Name issue = new X500Name("C=CN");
		generator.setIssuer(issue);
		generator.setIssuerUniqueID(new DERBitString(1));
		//使用者
		X500Name subject = new X500Name("C=CN");
		generator.setSubject(subject);
		generator.setSubjectUniqueID(new DERBitString(1));
		
		//设置SubjectPublicKeyInfo
		AlgorithmIdentifier alg = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"), DERNull.INSTANCE);
		SubjectPublicKeyInfo spi = new SubjectPublicKeyInfo(alg,  new DERBitString(generatePubKey()));
		generator.setSubjectPublicKeyInfo(spi);
		
		//设置Signature
		AlgorithmIdentifier alg1 = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"));
		generator.setSignature(alg1);
		
		//设置扩展
		Extension ext = new Extension(Extension.basicConstraints, true, "123".getBytes());
		generator.setExtensions(new Extensions(new Extension[]{ext}));
		
		tbCert = generator.generateTBSCertificate();
		
		
		
		//创建AlgorithmIdentifier
		ai = new AlgorithmIdentifier(new ASN1ObjectIdentifier("1.2.840.113549.1.1.5"), DERNull.INSTANCE);
		
		
		//创建signature
		signature = new DERBitString("123".getBytes());
		
		
		ASN1Encodable[] arrays = {tbCert, ai, signature};
		cert = new DERSequence(arrays);
		
		String certStr = new String(Base64.encodeBase64(cert.getEncoded()), "UTF-8");
		System.out.println("证书内容为: ");
		System.out.println(certStr);
	}
	
	
	public static byte[] generatePubKey() throws Exception{
		// 实例化密钥对儿生成器
				KeyPairGenerator keyPairGen = KeyPairGenerator
						.getInstance("RSA");

				// 初始化密钥对儿生成器
				keyPairGen.initialize(512);

				// 生成密钥对儿
				KeyPair keyPair = keyPairGen.generateKeyPair();

				// 公钥
				RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
				
				return publicKey.getEncoded();
	}

	/**
	 * @param args
	 * @throws Exception 
	 */
	public static void main(String[] args) throws Exception {
		makeCert();
	}
}
