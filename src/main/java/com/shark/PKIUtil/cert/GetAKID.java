package com.shark.PKIUtil.cert;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;

import java.security.cert.X509Certificate;

/**
 * Created by liuqinghua on 2016-12-19.
 */
public class GetAKID {
    /**
     * 获取证书中的颁发者密钥标识
     * @param certobj
     * @return
     */
    public static byte[] GetAKID(X509Certificate certobj)
    {
        try{
            byte[] akid= certobj.getExtensionValue("2.5.29.35");
            if(akid==null)
                return null;
            DEROctetString oct= (DEROctetString) DEROctetString.fromByteArray(akid);
            akid= oct.getOctets();
            //tmp= HexEncoder.encode(akid);
            AuthorityKeyIdentifier akidobj= AuthorityKeyIdentifier.getInstance(akid);
            akid= akidobj.getKeyIdentifier();
            return akid;
        }catch(Exception e){
            return null;
        }
    }
}
