package com.shark.PKIUtil.cert;

import org.apache.commons.codec.digest.DigestUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.tsp.*;
import org.bouncycastle.util.Store;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.Collection;
import java.util.Iterator;

/**
 * 参考文档：https://tools.ietf.org/html/rfc3161
 * Created by liuqinghua on 2016-12-30.
 */
public class TimeStamp {
    /**
     * 从 TSA 服务器获取 时间戳签名
     * @param data 待提交给 TSA服务器签名的原文内容
     */
    public void getTimeStampToken(byte[] data) throws IOException, Exception{
        //1.构造 时间戳请求
        TimeStampRequestGenerator timeStampRequestGenerator = new TimeStampRequestGenerator();
        timeStampRequestGenerator.setCertReq(true);
        timeStampRequestGenerator.setReqPolicy(new ASN1ObjectIdentifier("XX.XX"));
        //2.16.840.1.101.3.4.2.1 为 SHA256算法
        byte[] digst = DigestUtils.sha256(data);
        TimeStampRequest timeStampRequest = timeStampRequestGenerator.generate(new ASN1ObjectIdentifier("2.16.840.1.101.3.4.2.1"), digst);

        String url = "";//TSA 服务器地址
        byte[] resp = this.getTimeStampResp(url, timeStampRequest.getEncoded());
        TimeStampResponse tsrp = new TimeStampResponse(resp);
        if(tsrp.getStatus() != 0 || tsrp.getStatus() != 1){
             System.out.println(tsrp.getStatusString());
             PKIFailureInfo fail = tsrp.getFailInfo();
             System.out.println(fail.toString());
        }

        TimeStampToken tst = tsrp.getTimeStampToken();
        this.verify(data,tst);
    }

    /**
     * 验证时间戳签名
     * @param  data
     * @param tst
     */
    private void verify(byte[] data,TimeStampToken tst) throws Exception{
        //得到 时间戳之后，先进行SignedData验证，时间戳token 本质上是一个 CMS结构(SignedData)
        CMSSignedData s = tst.toCMSSignedData();
        Store certStore = s.getCertificates();
        SignerInformationStore signers = s.getSignerInfos();
        Collection c = signers.getSigners();
        int size = c.size();
        Iterator it = c.iterator();
        int verified = 0;
        while (it.hasNext()) {//对SignedData中的 每一个签名进行验证
            SignerInformation signer = (SignerInformation)it.next();
            Collection          certCollection = certStore.getMatches(signer.getSID());

            Iterator              certIt = certCollection.iterator();
            X509CertificateHolder cert = (X509CertificateHolder)certIt.next();

            if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(cert))){
                verified++;
            }
        }
        if(size != verified){
            throw new Exception("SignedData 验证不通过");
        }
        //验证 SignedData 通过之后，需要获取 TSTInfo,并验证tsi中的信息和原来 request中data信息一致
        TimeStampTokenInfo tsi = tst.getTimeStampInfo();
        ASN1ObjectIdentifier asn1ObjectIdentifier = tsi.getMessageImprintAlgOID();
        //因为请求使用 SHA256 请求的，如果响应中不是此算法，则不对
        if(!"2.16.840.1.101.3.4.2.1".equals(asn1ObjectIdentifier.getId())){
            throw new Exception("摘要算法不正确");
        }
        byte[] digst = DigestUtils.sha256(data);
        byte[] digest = tsi.getMessageImprintDigest();
        if(!Arrays.equals(digst, digest)){
            throw  new Exception("时间戳签名的摘要信息不对");
        }

    }

    /**
     * 从时间戳服务器获取时间戳签名
     * @param url
     * @param req
     * @return
     * @throws Exception
     */
    private byte[] getTimeStampResp(String url, byte[] req) throws Exception{
        URL urlObj=new URL(url);
        URLConnection conn=urlObj.openConnection();
        if(conn instanceof HttpURLConnection ==false) {
            throw new Exception("not http url");
        }
        HttpURLConnection httpConn=(HttpURLConnection)conn;
        httpConn.setRequestMethod("POST");
        httpConn.setRequestProperty("Content-Type", "application/timestamp-query");
        httpConn.addRequestProperty("Content-Length", req.length+"");
        httpConn.setDoOutput(true);

        httpConn.connect();

        OutputStream out = httpConn.getOutputStream();
        out.write(req);
        out.close();

        int status=httpConn.getResponseCode();
        if(status!=HttpURLConnection.HTTP_OK) {
            httpConn.disconnect();
            throw new Exception("bad http status "+status);
        }

        String nLenStr=httpConn.getHeaderField("Content-Length");
        if(nLenStr==null) {
            httpConn.disconnect();
            throw new Exception("no content length");
        }

        int nLen = java.lang.Integer.parseInt(nLenStr);
        byte []resp=new byte[nLen];
        int ic;
        BufferedInputStream bis=new BufferedInputStream(httpConn.getInputStream());
        for ( int i = 0 ;i < nLen ; i++ ) {
            ic = bis.read();
            if(ic==-1) {
                bis.close();
                httpConn.disconnect();
                throw new Exception("bad resp");
            }

            resp[i]=(byte)ic;
        }

        bis.close();
        httpConn.disconnect();
        return resp;
    }
}
