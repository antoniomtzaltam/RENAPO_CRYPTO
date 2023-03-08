/*     */ package mx.gob.renapo.crypto.service;
/*     */ 
/*     */ import java.io.File;
/*     */ import java.io.FileInputStream;
/*     */ import java.io.IOException;
/*     */ import java.io.InputStream;
/*     */ import java.security.KeyStore;
/*     */ import java.security.KeyStoreException;
/*     */ import java.security.NoSuchAlgorithmException;
/*     */ import java.security.PrivateKey;
/*     */ import java.security.Provider;
/*     */ import java.security.Security;
/*     */ import java.security.UnrecoverableKeyException;
/*     */ import java.security.cert.CertificateException;
/*     */ import java.security.cert.CertificateFactory;
/*     */ import java.security.cert.X509Certificate;
/*     */ import java.util.Enumeration;
/*     */ import mx.gob.renapo.crypto.exception.GenerarArchivoPKCS7Exception;
/*     */ import org.apache.log4j.Logger;
/*     */ import org.bouncycastle.asn1.ASN1ObjectIdentifier;
/*     */ import org.bouncycastle.cms.CMSAlgorithm;
/*     */ import org.bouncycastle.cms.CMSCompressedData;
/*     */ import org.bouncycastle.cms.CMSCompressedDataGenerator;
/*     */ import org.bouncycastle.cms.CMSEnvelopedData;
/*     */ import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
/*     */ import org.bouncycastle.cms.CMSException;
/*     */ import org.bouncycastle.cms.CMSProcessableByteArray;
/*     */ import org.bouncycastle.cms.CMSProcessableFile;
/*     */ import org.bouncycastle.cms.CMSSignedData;
/*     */ import org.bouncycastle.cms.CMSSignedDataGenerator;
/*     */ import org.bouncycastle.cms.CMSTypedData;
/*     */ import org.bouncycastle.cms.RecipientInfoGenerator;
/*     */ import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
/*     */ import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
/*     */ import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
/*     */ import org.bouncycastle.cms.jcajce.ZlibCompressor;
/*     */ import org.bouncycastle.jce.provider.BouncyCastleProvider;
/*     */ import org.bouncycastle.operator.ContentSigner;
/*     */ import org.bouncycastle.operator.DigestCalculatorProvider;
/*     */ import org.bouncycastle.operator.OperatorCreationException;
/*     */ import org.bouncycastle.operator.OutputCompressor;
/*     */ import org.bouncycastle.operator.OutputEncryptor;
/*     */ import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
/*     */ import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
/*     */ 
/*     */ public class PKCS7ServiceImpl implements PKCS7Service {
/*  47 */   private static Logger log = Logger.getLogger(PKCS7ServiceImpl.class);
/*  48 */   private final String KEYSTORE_FORMAT = "PKCS12";
/*  49 */   private final String CERTIFICATE_FORMAT = "X.509";
/*  50 */   private final String PROVIDER_NAME = "BC";
/*  51 */   private final String SIGNATURE_ALGORITHM_NAME = "SHA1withRSA";
/*  52 */   private final ASN1ObjectIdentifier CIPHER_ALGORITHM_NAME = CMSAlgorithm.AES256_CBC;
/*     */   
/*     */   public PKCS7ServiceImpl() {
/*  55 */     Security.addProvider((Provider)new BouncyCastleProvider());
/*     */   }
/*     */ 
/*     */   
/*     */   public byte[] generateFile(File keystore, String pin, File nist, File certificate) throws GenerarArchivoPKCS7Exception {
/*     */     try {
/*  61 */       CMSSignedData signedData = signFile(keystore, pin, nist);
/*  62 */       CMSCompressedData compressedData = compressFile(signedData);
/*  63 */       CMSEnvelopedData envelopedData = envelopeFile(compressedData, certificate);
/*  64 */       return envelopedData.getEncoded();
/*  65 */     } catch (Exception ex) {
/*  66 */       log.error(ex.getCause());
/*  67 */       throw new GenerarArchivoPKCS7Exception("Error al generar el archivo PKCS7");
/*     */     } 
/*     */   }
/*     */ 
/*     */ 
/*     */   
/*     */   public boolean verifyKeystore(File keystore, String pin) {
/*     */     try {
/*  75 */       KeyStore ks = KeyStore.getInstance("PKCS12");
/*  76 */       FileInputStream fis = new FileInputStream(keystore);
/*  77 */       ks.load(fis, pin.toCharArray());
/*  78 */       Enumeration<String> aliases = ks.aliases();
/*  79 */       String alias = aliases.nextElement();
/*  80 */       PrivateKey privKey = (PrivateKey)ks.getKey(alias, 
/*  81 */           pin.toCharArray());
/*  82 */       if (privKey == null) {
/*  83 */         return false;
/*     */       }
/*  85 */       return true;
/*  86 */     } catch (Exception ex) {
/*  87 */       log.error(ex.getCause());
/*  88 */       return false;
/*     */     } 
/*     */   }
/*     */ 
/*     */   
/*     */   private CMSEnvelopedData envelopeFile(CMSCompressedData compressedData, File certificate) throws CertificateException, IOException, CMSException {
/*  94 */     InputStream inStream = new FileInputStream(certificate);
/*  95 */     CertificateFactory cf = CertificateFactory.getInstance("X.509");
/*  96 */     X509Certificate cert = (X509Certificate)cf
/*  97 */       .generateCertificate(inStream);
/*  98 */     inStream.close();
/*     */     
/* 100 */     CMSEnvelopedDataGenerator cmsEnvGen = new CMSEnvelopedDataGenerator();
/*     */     
/* 102 */     JceKeyTransRecipientInfoGenerator keyTransRec = new JceKeyTransRecipientInfoGenerator(cert);
/* 103 */     cmsEnvGen.addRecipientInfoGenerator((RecipientInfoGenerator)keyTransRec);
/*     */     
/* 105 */     CMSProcessableByteArray cMSProcessableByteArray = new CMSProcessableByteArray(
/* 106 */         compressedData.getEncoded());
/* 107 */     JceCMSContentEncryptorBuilder cmsEnc = new JceCMSContentEncryptorBuilder(this.CIPHER_ALGORITHM_NAME);
/* 108 */     OutputEncryptor outEnc = cmsEnc.build();
/*     */     
/* 110 */     return cmsEnvGen.generate((CMSTypedData)cMSProcessableByteArray, outEnc);
/*     */   }
/*     */   
/*     */   private CMSCompressedData compressFile(CMSSignedData signedData) throws CMSException, IOException {
/* 114 */     CMSCompressedDataGenerator cmsCompGen = new CMSCompressedDataGenerator();
/*     */     
/* 116 */     CMSProcessableByteArray cMSProcessableByteArray = new CMSProcessableByteArray(signedData.getEncoded());
/* 117 */     ZlibCompressor zlibCompressor = new ZlibCompressor();
/*     */     
/* 119 */     return cmsCompGen.generate((CMSTypedData)cMSProcessableByteArray, (OutputCompressor)zlibCompressor);
/*     */   }
/*     */ 
/*     */ 
/*     */   
/*     */   private CMSSignedData signFile(File keystore, String pin, File nist) throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, OperatorCreationException, CMSException {
/* 125 */     KeyStore ks = KeyStore.getInstance("PKCS12");
/* 126 */     FileInputStream fis = new FileInputStream(keystore);
/* 127 */     ks.load(fis, pin.toCharArray());
/*     */     
/* 129 */     PrivateKey privKey = null;
/* 130 */     X509Certificate cert = null;
/*     */     
/* 132 */     Enumeration<String> aliases = ks.aliases();
/* 133 */     if (aliases.hasMoreElements()) {
/* 134 */       String alias = aliases.nextElement();
/* 135 */       privKey = (PrivateKey)ks.getKey(alias, pin.toCharArray());
/* 136 */       cert = (X509Certificate)ks.getCertificate(alias);
/*     */     } 
/*     */     
/* 139 */     CMSSignedDataGenerator cmsSignGen = new CMSSignedDataGenerator();
/*     */     
/* 141 */     CMSProcessableFile cMSProcessableFile = new CMSProcessableFile(nist);
/*     */     
/* 143 */     JcaDigestCalculatorProviderBuilder digestCalcBuilder = (new JcaDigestCalculatorProviderBuilder())
/* 144 */       .setProvider("BC");
/* 145 */     DigestCalculatorProvider digestCalc = digestCalcBuilder.build();
/* 146 */     JcaSignerInfoGeneratorBuilder signerInfo = new JcaSignerInfoGeneratorBuilder(
/* 147 */         digestCalc);
/*     */     
/* 149 */     JcaContentSignerBuilder contentSignBuilder = (new JcaContentSignerBuilder(
/* 150 */         "SHA1withRSA")).setProvider("BC");
/* 151 */     ContentSigner sha1Signer = contentSignBuilder.build(privKey);
/*     */     
/* 153 */     cmsSignGen.addSignerInfoGenerator(signerInfo.build(sha1Signer, cert));
/*     */     
/* 155 */     return cmsSignGen.generate((CMSTypedData)cMSProcessableFile, true);
/*     */   }
/*     */ }


/* Location:              C:\Trabajo\P7M\PKCS7Generator.jar!\mx\gob\renapo\crypto\service\PKCS7ServiceImpl.class
 * Java compiler version: 6 (50.0)
 * JD-Core Version:       1.1.3
 */