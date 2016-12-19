package com.shark.PKIUtil.cert;

import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.HttpStatus;
import org.apache.commons.httpclient.methods.GetMethod;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.SocketTimeoutException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509CRLEntry;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Iterator;
import java.util.Set;

/**
 * 一般情况下需要从证书扩展中获取 CRL地址
 * 处理证书的CRL逻辑
 * Created by liuqinghua on 2016-12-19.
 */
public class ParseCRL {

    /**
     * 传入 CRL 的URL地址
     * @param url
     * @return
     */
    public static byte[] getCRLByUrl(String url){
        ByteArrayInputStream bis = null;
        try{
            byte[] crlBytes = http_get(url);
            if(crlBytes != null){
                bis = new ByteArrayInputStream(crlBytes);
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509CRL aCrl = (X509CRL) cf.generateCRL(bis);

                /**
                 * 从CRL中获取颁发者密钥标识符
                 */
                byte[] akid= aCrl.getExtensionValue("2.5.29.35");

                DEROctetString oct= (DEROctetString) DEROctetString.fromByteArray(akid);
                akid= oct.getOctets();
                AuthorityKeyIdentifier akidobj= AuthorityKeyIdentifier.getInstance(akid);
                akid= akidobj.getKeyIdentifier();

                String hexakid= Hex.encodeHexString(akid);
                System.out.println("颁发者密钥标识符 " + hexakid);
                Date thisDate = aCrl.getThisUpdate();
                System.out.println("CRL当次更新时间 " + thisDate);

                Date nextDate = aCrl.getNextUpdate();

                System.out.println("CRL下次更新时间 " + nextDate);

                System.out.println("===================================");

                Set tSet = aCrl.getRevokedCertificates();
                Iterator tIterator = tSet.iterator();
                while (tIterator.hasNext()) {
                    X509CRLEntry tEntry = (X509CRLEntry) tIterator.next();
                    String sn = tEntry.getSerialNumber().toString(16).toUpperCase();
                    String issName = aCrl.getIssuerDN().toString();
                    String time = new SimpleDateFormat("yyyyMMddHHmmss").format (tEntry.getRevocationDate());
                    System.out.println("证书序列号" + sn);
                    System.out.println(issName);
                    System.out.println("注销时间" + time);
                    System.out.println("***************************");
                }

                return aCrl.getEncoded();
            }
        }catch(Exception e){
            e.printStackTrace();
        }

        return null;
    }



    public static byte[] http_get(String url){
        GetMethod getMethod = null;
        int responseStatus = -1; //上传新浪返回的状态码
        try{
            HttpClient client = new HttpClient();
            int timeOut = 50000;

            client.getHttpConnectionManager().getParams().setConnectionTimeout(timeOut);
            client.getHttpConnectionManager().getParams().setSoTimeout(timeOut);

            getMethod = new GetMethod(url);

            responseStatus = client.executeMethod(getMethod);
            byte[] respContent = getMethod.getResponseBody();
            if(HttpStatus.SC_OK == responseStatus){
                if(respContent != null){
                    return respContent;
                }

            }
        }catch(ConnectTimeoutException e){
            e.printStackTrace();
        }catch(SocketTimeoutException e){
            e.printStackTrace();
        }catch(FileNotFoundException e){
            e.printStackTrace();
        }catch(IOException e){
            e.printStackTrace();
        }catch(Exception e){
            e.printStackTrace();
        }finally{
            if(getMethod != null) getMethod.releaseConnection();
        }
        return null;
    }
}
