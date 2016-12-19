package com.shark.PKIUtil.cert;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.ocsp.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;

import java.io.BufferedOutputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;

/**
 * 处理证书 OCSP响应，一般情况下 从证书扩展中获取 OCSP 地址
 * Created by liuqinghua on 2016-12-19.
 * OCSP的请求和响应结构具体参考 : https://tools.ietf.org/html/rfc2560
 */
public class ParseOCSP {

    /**
     *
     * @param certbecheck 待检测的证书
     * @param ocspcert    OCSP的证书，用于 验证获取到的OCSP响应处理，
     * @param ocspurl
     */
    public static void check(X509Certificate certbecheck, X509Certificate ocspcert, String ocspurl) {
        try{
            //generate ocsp request
            AlgorithmIdentifier hashalg= new AlgorithmIdentifier(X509ObjectIdentifiers.id_SHA1, DERNull.INSTANCE);

            byte[] cadnhash= Sha1Data(certbecheck.getIssuerX500Principal().getEncoded());
            DEROctetString issuerNameHash= new DEROctetString(cadnhash);

            byte[] cakeyhash= GetAKID.GetAKID(certbecheck);
            DEROctetString issuerKeyHash= new DEROctetString(cakeyhash);

            ASN1Integer serialNumber= new ASN1Integer(certbecheck.getSerialNumber());

            CertID reqCert= new CertID(hashalg, issuerNameHash, issuerKeyHash, serialNumber);

            Request request= new Request(reqCert,null);
            ASN1EncodableVector request_v = new ASN1EncodableVector();
            request_v.add(request);
            ASN1Sequence requestList=  new DERSequence(request_v);

            TBSRequest tbsRequest= new TBSRequest(null,requestList,(Extensions)null);
            OCSPRequest ocspRequ= new OCSPRequest(tbsRequest, null);

            //http request
            byte[] array = ocspRequ.getEncoded();
            if(!ocspurl.startsWith("http"))
                throw new Exception("Only http is supported for ocsp calls");

            HttpURLConnection con;
            URL url = new URL(ocspurl);
            con = (HttpURLConnection) url.openConnection();
            con.setRequestProperty("Content-Type", "application/ocsp-request");
            con.setRequestProperty("Accept", "application/ocsp-response");
            con.setDoOutput(true);
            OutputStream out = con.getOutputStream();
            DataOutputStream dataOut = new DataOutputStream(new BufferedOutputStream(out));
            dataOut.write(array);
            dataOut.flush();
            dataOut.close();

            //parse ocsp response
            InputStream in = (InputStream) con.getContent();
            ASN1InputStream asn1in= new ASN1InputStream(in);
            OCSPResponse ocspResponse = OCSPResponse.getInstance(asn1in.readObject());
            asn1in.close();

            //to CertVerifyStatusVO
            BigInteger responseStatus= ocspResponse.getResponseStatus().getValue();
            if(!responseStatus.equals(BigInteger.ZERO))	//NOT SUCCESSFUL
            {
                System.out.println("OCSP响应错误");
                return ;
            }

            ASN1ObjectIdentifier responseType= ocspResponse.getResponseBytes().getResponseType();
            ASN1OctetString response= ocspResponse.getResponseBytes().getResponse();
            if(!responseType.equals(OCSPObjectIdentifiers.id_pkix_ocsp_basic))
                throw new Exception("OCSP响应非BasicOCSPResponse类型");

            BasicOCSPResponse baseResp= BasicOCSPResponse.getInstance(response.getOctets());
            if(ocspcert!=null)
            {
                byte[] content= baseResp.getTbsResponseData().getEncoded();
                String algoid= baseResp.getSignatureAlgorithm().getAlgorithm().getId();
                byte[] signature= baseResp.getSignature().getBytes();
                baseResp.getCerts();
                //TODO verify signature
            }
            ResponseData tbsResponseData= baseResp.getTbsResponseData();
            ASN1Sequence responses= tbsResponseData.getResponses();
            for(int i=0; i<responses.size(); i++)
            {
                SingleResponse singleResp= SingleResponse.getInstance(responses.getObjectAt(i));
                //
                CertID certid= singleResp.getCertID();
                if(certid.equals(reqCert))
                {
                    CertStatus certStatus= singleResp.getCertStatus();
                    switch(certStatus.getTagNo())
                    {
                        case 0:
                            System.out.println("证书没有问题");
                            break;
                        case 1:
                            System.out.println("证书注销");
                            break;
                        case 2:
                            System.out.println("证书状态未知");
                            break;
                        default:
                    }
                }
            }
            throw new Exception("OCSP响应CertID不匹配");
        }catch(Exception e){
            e.printStackTrace();
        }
    }
    private static byte[] Sha1Data(byte[] data) throws Exception {
        MessageDigest md= MessageDigest.getInstance("SHA1");
        return md.digest(data);
    }

}
