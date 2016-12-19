package com.shark.PKIUtil.cert;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.TBSCertificate;

/**
 * 主题项工具类
 */
class SubjectUtil {
	public static String CN_OID = "2.5.4.3";
	public static String O_OID = "2.5.4.10";
	public static String L_OID = "2.5.4.7";
	public static String E_OID = "1.2.840.113549.1.9.1";
	public static String S_OID = "2.5.4.6";
	public static String C_OID = "2.5.4.8";

	/**
	 * 获取主题项的键和值，返回的 内容是 一个Map，key为主题项的OID值，value为主题项的Value值
	 * @param subject X509证书
	 * @return
	 * @throws IOException
	 */
	public static Map<String , String> getSubjectMap(X500Name subject) throws IOException{
		
		Map<String ,String> result = new HashMap<String ,String>();

		RDN[] rdns = subject.getRDNs();
		for(RDN rdn:rdns){
			AttributeTypeAndValue typeValue = rdn.getFirst();
			result.put(typeValue.getType().toString(), typeValue.getValue().toString());
		}
		return result;
	}
}
